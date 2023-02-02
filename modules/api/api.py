# -*- coding: utf-8 -*-
import base64
import io, os
import time
import json
import datetime
import uvicorn
from threading import Lock
from io import BytesIO
from datetime import datetime, timedelta

from gradio.processing_utils import decode_base64_to_file
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, select_autoescape, PackageLoader, FileSystemLoader

from secrets import compare_digest
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException

import modules.shared as shared
from modules import sd_samplers, deepbooru, sd_hijack, images, scripts, ui, postprocessing
from modules.api.models import *
from modules.processing import StableDiffusionProcessingTxt2Img, StableDiffusionProcessingImg2Img, process_images
from modules.textual_inversion.textual_inversion import create_embedding, train_embedding
from modules.textual_inversion.preprocess import preprocess
from modules.hypernetworks.hypernetwork import create_hypernetwork, train_hypernetwork
from PIL import PngImagePlugin,Image
from modules.sd_models import checkpoints_list
from modules.sd_models_config import find_checkpoint_config_near_filename
from modules.realesrgan_model import get_realesrgan_models
from modules import devices
from typing import List, Union

from passlib.context import CryptContext
from sqlalchemy.orm import Session
import sqlalchemy.exc as exc
from sqlalchemy.orm.exc import FlushError

from .database import engine, get_db
from . import models, credits, styles
from .users import *
from .auth import *
from .logs import print_message
from .config import settings
from . import utils as api_utils

models.Base.metadata.create_all(bind=engine)

DEFAULT_CREDITS = settings.DEFAULT_CREDITS                     
CREDITS_PER_IMAGE = settings.CREDITS_PER_IMAGE
with open('./modules/api/conf/config.json', 'r') as f:
    IMEZY_CONFIG = json.load(f)
import piexif
import piexif.helper

def upscaler_to_index(name: str):
    try:
        return [x.name.lower() for x in shared.sd_upscalers].index(name.lower())
    except:
        raise HTTPException(status_code=400, detail=f"Invalid upscaler, needs to be on of these: {' , '.join([x.name for x in sd_upscalers])}")

def script_name_to_index(name, scripts):
    try:
        return [script.title().lower() for script in scripts].index(name.lower())
    except:
        raise HTTPException(status_code=422, detail=f"Script '{name}' not found")

def validate_sampler_name(name):
    config = sd_samplers.all_samplers_map.get(name, None)
    if config is None:
        raise HTTPException(status_code=404, detail="Sampler not found")

    return name

def setUpscalers(req: dict):
    reqDict = vars(req)
    reqDict['extras_upscaler_1'] = reqDict.pop('upscaler_1', None)
    reqDict['extras_upscaler_2'] = reqDict.pop('upscaler_2', None)
    return reqDict

def decode_base64_to_image(encoding):
    if encoding.startswith("data:image/"):
        encoding = encoding.split(";")[1].split(",")[1]
    try:
        image = Image.open(BytesIO(base64.b64decode(encoding)))
        return image
    except Exception as err:
        raise HTTPException(status_code=500, detail="Invalid encoded image")

def encode_pil_to_base64(image):
    with io.BytesIO() as output_bytes:

        if opts.samples_format.lower() == 'png':
            use_metadata = False
            metadata = PngImagePlugin.PngInfo()
            for key, value in image.info.items():
                if isinstance(key, str) and isinstance(value, str):
                    metadata.add_text(key, value)
                    use_metadata = True
            image.save(output_bytes, format="PNG", pnginfo=(metadata if use_metadata else None), quality=opts.jpeg_quality)

        elif opts.samples_format.lower() in ("jpg", "jpeg", "webp"):
            parameters = image.info.get('parameters', None)
            exif_bytes = piexif.dump({
                "Exif": { piexif.ExifIFD.UserComment: piexif.helper.UserComment.dump(parameters or "", encoding="unicode") }
            })
            if opts.samples_format.lower() in ("jpg", "jpeg"):
                image.save(output_bytes, format="JPEG", exif = exif_bytes, quality=opts.jpeg_quality)
            else:
                image.save(output_bytes, format="WEBP", exif = exif_bytes, quality=opts.jpeg_quality)

        else:
            raise HTTPException(status_code=500, detail="Invalid image format")

        bytes_data = output_bytes.getvalue()

    return base64.b64encode(bytes_data)

def convert_img_to_webp(image):
    with io.BytesIO() as output_bytes:
        image.save(output_bytes, "WEBP")
        bytes_data = output_bytes.getvalue()
    return base64.b64encode(bytes_data)
    
def api_middleware(app: FastAPI):
    @app.middleware("http")
    async def log_and_time(req: Request, call_next):
        ts = time.time()
        res: Response = await call_next(req)
        duration = str(round(time.time() - ts, 4))
        res.headers["X-Process-Time"] = duration
        endpoint = req.scope.get('path', 'err')
        if shared.cmd_opts.api_log and endpoint.startswith('/sdapi'):
            print('API {t} {code} {prot}/{ver} {method} {endpoint} {cli} {duration}'.format(
                t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                code = res.status_code,
                ver = req.scope.get('http_version', '0.0'),
                cli = req.scope.get('client', ('0:0.0.0', 0))[0],
                prot = req.scope.get('scheme', 'err'),
                method = req.scope.get('method', 'err'),
                endpoint = endpoint,
                duration = duration,
            ))
        return res

class Api:
    def __init__(self, app: FastAPI, queue_lock: Lock):
        if shared.cmd_opts.api_auth:
            self.credentials = dict()
            for auth in shared.cmd_opts.api_auth.split(","):
                user, password = auth.split(":")
                self.credentials[user] = password

        self.router = APIRouter()
        self.app = app
        self.queue_lock = queue_lock
        api_middleware(self.app) # 이메일 인증이 필요한 기능은 ## 표시
        self.add_api_route("/sdapi/v1/txt2img", self.text2imgapi, methods=["POST"], response_model=TextToImageResponse)
        self.add_api_route("/sdapi/v1/txt2img-auth", self.text2imgapi_auth, methods=["POST"], response_model=models.TextToImageAuthResponse) ##
        self.add_api_route("/sdapi/v1/img2img", self.img2imgapi, methods=["POST"], response_model=ImageToImageResponse)
        self.add_api_route("/sdapi/v1/img2img-auth", self.img2imgapi_auth, methods=["POST"], response_model=models.ImageToImageAuthResponse) ##
        self.add_api_route("/sdapi/v1/extra-single-image", self.extras_single_image_api, methods=["POST"], response_model=ExtrasSingleImageResponse)
        self.add_api_route("/sdapi/v1/extra-single-image-auth", self.extras_single_image_api_auth, methods=["POST"], response_model=ExtrasSingleImageResponse) ##
        self.add_api_route("/sdapi/v1/extra-batch-images", self.extras_batch_images_api, methods=["POST"], response_model=ExtrasBatchImagesResponse)
        self.add_api_route("/sdapi/v1/png-info", self.pnginfoapi, methods=["POST"], response_model=PNGInfoResponse)
        self.add_api_route("/sdapi/v1/progress", self.progressapi, methods=["GET"], response_model=ProgressResponse)
        self.add_api_route("/sdapi/v1/interrogate", self.interrogateapi, methods=["POST"])
        self.add_api_route("/sdapi/v1/interrupt", self.interruptapi, methods=["POST"])
        self.add_api_route("/sdapi/v1/skip", self.skip, methods=["POST"])
        self.add_api_route("/sdapi/v1/options", self.get_config, methods=["GET"], response_model=OptionsModel)
        self.add_api_route("/sdapi/v1/options", self.set_config, methods=["POST"])
        self.add_api_route("/sdapi/v1/cmd-flags", self.get_cmd_flags, methods=["GET"], response_model=FlagsModel)
        self.add_api_route("/sdapi/v1/samplers", self.get_samplers, methods=["GET"], response_model=List[SamplerItem])
        self.add_api_route("/sdapi/v1/upscalers", self.get_upscalers, methods=["GET"], response_model=List[UpscalerItem])
        self.add_api_route("/sdapi/v1/sd-models", self.get_sd_models, methods=["GET"], response_model=List[SDModelItem])
        self.add_api_route("/sdapi/v1/hypernetworks", self.get_hypernetworks, methods=["GET"], response_model=List[HypernetworkItem])
        self.add_api_route("/sdapi/v1/face-restorers", self.get_face_restorers, methods=["GET"], response_model=List[FaceRestorerItem])
        self.add_api_route("/sdapi/v1/realesrgan-models", self.get_realesrgan_models, methods=["GET"], response_model=List[RealesrganItem])
        self.add_api_route("/sdapi/v1/prompt-styles", self.get_prompt_styles, methods=["GET"], response_model=List[PromptStyleItem])
        self.add_api_route("/sdapi/v1/embeddings", self.get_embeddings, methods=["GET"], response_model=EmbeddingsResponse)
        self.add_api_route("/sdapi/v1/refresh-checkpoints", self.refresh_checkpoints, methods=["POST"])
        self.add_api_route("/sdapi/v1/create/embedding", self.create_embedding, methods=["POST"], response_model=CreateResponse)
        self.add_api_route("/sdapi/v1/create/hypernetwork", self.create_hypernetwork, methods=["POST"], response_model=CreateResponse)
        self.add_api_route("/sdapi/v1/preprocess", self.preprocess, methods=["POST"], response_model=PreprocessResponse)
        self.add_api_route("/sdapi/v1/train/embedding", self.train_embedding, methods=["POST"], response_model=TrainResponse)
        self.add_api_route("/sdapi/v1/train/hypernetwork", self.train_hypernetwork, methods=["POST"], response_model=TrainResponse)
        self.add_api_route("/sdapi/v1/memory", self.get_memory, methods=["GET"], response_model=MemoryResponse)

        self.add_api_route("/user/create", self.create_new_user, methods=["POST"])
        self.add_api_route("/user/login", self.login, methods=["POST"])
        # self.add_api_route("/user/get_access_token", self.get_access_token, methods=["GET"])
        self.add_api_route("/user/reissue", self.reissue_access_token, methods=["POST"]) # reissue access token
        self.add_api_route("/user/logout", self.logout, methods=["POST"]) # logout
        self.add_api_route("/user/read_user_info", self.read_user_info, methods=["GET"])
        self.add_api_route("/user/read/{user_id}", self.read_user_by_id, methods=["GET"])
        self.add_api_route("/user/read_all", self.read_all_users, methods=["GET"]) # read all users
        self.add_api_route("/user/update_password", self.update_password, methods=["PUT"], response_model=UpdatePasswordResponse)
        self.add_api_route("/user/update_email", self.update_email, methods=["PUT"])
        self.add_api_route("/user/update_username", self.update_username, methods=["PUT"])
        self.add_api_route("/user/update/{user_id}", self.update_user_by_id, methods=["PUT"])
        self.add_api_route("/user/delete/{user_id}", self.delete_user_by_id, methods=["DELETE"])
        self.add_api_route("/user/make_admin/{user_id}", self.make_admin, methods=["PUT"])
        
        self.add_api_route("/credits/read/all", self.read_all_creds, methods=["GET"])
        self.add_api_route("/credits/read", self.read_cred_by_id, methods=["GET"])
        self.add_api_route("/credits/update", self.update_cred, methods=["PUT"], response_model=UpdateCreditsResponse)
        
        self.add_api_route("/image/search", self.search_image, methods=["GET"])
        self.add_api_route("/image/search_compressed", self.search_image_compressed, methods=["GET"])
        self.add_api_route("/image/delete/{image_id}", self.delete_image, methods=["DELETE"])
        self.add_api_route("/image/download/{image_id}", self.download_image, methods=["GET"])
        
        self.add_api_route("/email/verification/send", self.email_verification_send, methods=["POST"]) # send verification code
        self.add_api_route("/email/verification/check", self.email_verification_check, methods=["PUT"]) # check verification code
        self.add_api_route("/email/verification/change", self.email_verification_change_check, methods=["POST"]) # resend verification code
        self.add_api_route("/email/feedback/send", self.feedback_email_send, methods=["POST"]) # send feedback email
        self.add_api_route("/email/send", self.send_email, methods=["POST"])
        
        self.add_api_route("/style/modifier", self.modifiers_read, methods=["GET"])
        self.add_api_route("/style/modifier/{modifier}", self.modifiers_read, methods=["GET"])
        # self.add_api_route("/style/modifier/create", self.create_modifier, methods=["POST"])
        # self.add_api_route("/style/modifier/update/{modifier_id}", self.update_modifier_by_id, methods=["PUT"])
        self.add_api_route("/style/style", self.styles_read, methods=["GET"])
        
        self.add_api_route("/payment/orderNames", self.get_order_names, methods=["GET"])
        self.add_api_route("/payment/orderNames/credits", self.get_order_names_credits, methods=["GET"])
        self.add_api_route("/payment/orderNames/subs", self.get_order_names_subs, methods=["GET"])
        self.add_api_route("/payment/history", self.get_payment_history, methods=["GET"])
        self.add_api_route("/payment/history/{email}", self.get_payment_history_email, methods=["GET"])
        self.add_api_route("/payment/order_id/generate/{order_name}", self.generate_order_id, methods=["GET"])
        self.add_api_route("/payment/toss/confirm", self.toss_confirm, methods=["POST"])
        
    # def get_res_codes(self):
    #     return {"response_codes": Responses.res_codes}
    
    def get_order_names(self, item_id: int = None, db: Session = Depends(get_db)):
        return api_utils.get_items(item_id,db = db)
    
    def get_order_names_credits(self, item_id: int = None, db: Session = Depends(get_db)):
        return api_utils.get_items(item_id,db = db, payment_class="credits")
    
    def get_order_names_subs(self, item_id: int = None, db: Session = Depends(get_db)):
        return api_utils.get_items(item_id,db = db, payment_class="subs")
    
    def generate_order_id(self, order_name: str):
        # order_id = f"imezy_{order_name}_{api_utils.get_random_string(16)}"
        order_id = api_utils.generate_order_id(order_name)
        print_message(f"order_id: {order_id}")
        return {"order_id": order_id}
    
    def get_payment_history(self, db: Session = Depends(get_db), auth: dict = Depends(access_token_auth)):
        print_message("get_payment_history", auth["email"])
        email = auth['email']
        
        return api_utils.get_payment_history(email, db = db)
    
    def get_payment_history_email(self, email: str, db: Session = Depends(get_db)):
        print_message("get_payment_history_email", email)
        
        return api_utils.get_payment_history(email, db = db)
    
    def toss_confirm(self, req: TossConfirmRequest, db: Session = Depends(get_db), auth: dict = Depends(access_token_auth)):
        print_message(f"toss_confirm request: {req}")
        return api_utils.toss_confirm(req, db = db, email = auth['email'])
    
    def send_email(self, email: EmailSendRequest, db: Session = Depends(get_db)):
        print_message(f"Send email to {email.email}")
        api_utils.send_email(email.email, email.subject, email.content, attachments=email.attachments)

    def search_image(self, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        print_message("search_image", auth)
        
        imezy_update_db = db.query(models.ImezyUpdateDB).filter(models.ImezyUpdateDB.email == auth['email'])
        if imezy_update_db is None:
            return HTTPException(status_code=404, detail="No images found in the database.")
        
        response = []
        for i, row in enumerate(imezy_update_db):
            updated = datetime.strptime(str(row.updated), "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d%H%M%S") # db의 updated 시간을 파일명에 맞게 변환
            
            try:
                # 이미지 저장된 json 파일 읽기
                with open(f"generated/{IMEZY_CONFIG['imezy_type1'][str(row.imezy_type)]}/{auth['email']}/{updated}.json", "r") as f:
                    data = json.load(f)
                if data["images"]:
                    response.append({"info": data["info"], "updated": row.updated, "image_id": row.id, "images": data["images"] })
            except FileNotFoundError:
                print(f"generated/{auth['email']}/{updated}.json 파일이 없습니다.")
                return exceptions.get_file_not_exist_exception()
                 
        return response
    
    def search_image_compressed(self, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        print_message("search_image", auth)
        
        imezy_update_db = db.query(models.ImezyUpdateDB).filter(models.ImezyUpdateDB.email == auth['email'])
        if imezy_update_db is None:
            return HTTPException(status_code=404, detail="No images found in the database.")
        
        response = []
        for i, row in enumerate(imezy_update_db):
            updated = datetime.strptime(str(row.updated), "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d%H%M%S") # db의 updated 시간을 파일명에 맞게 변환
            
            try:
                # 이미지 저장된 json 파일 읽기
                with open(f"generated/{IMEZY_CONFIG['imezy_type1'][str(row.imezy_type)]}/{auth['email']}/{updated}.json", "r") as f:
                    data = json.load(f)
                if data["images_compressed"]:
                    response.append({"info": data["info"], "updated": row.updated, "image_id": row.id, "images": data["images_compressed"] })
            except FileNotFoundError:
                print(f"generated/{auth['email']}/{updated}.json 파일이 없습니다.")
                continue
            except KeyError:
                print(f"generated/{auth['email']}/{updated}.json 파일에 images_compressed가 없습니다.")
                continue
                 
        return response
    
    def delete_image(self, image_id: int, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        print_message(f"Delete image user: {auth['email']}, image_id: {image_id}")
        
        image_db = db.query(models.ImezyUpdateDB).filter(models.ImezyUpdateDB.id == image_id).first()
        if image_db is None:
            return {"detail": f"Delete image user: {auth['email']}, image_id: {image_id} is not exist"}
        elif image_db.email != auth['email']:
            return exceptions.get_inappropriate_user_exception()
        
        image_type =IMEZY_CONFIG['imezy_type1'][str(image_db.imezy_type)]
        image_updated = datetime.strptime(str(image_db.updated), "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d%H%M%S")
        try:
            os.remove(f"generated/{image_type}/{auth['email']}/{image_updated}.json")
        except FileNotFoundError:
            print_message(f"Delete image file image_id: {image_id} is not exist")
            return HTTPException(status_code=404, detail=f"Delete image file image_id: {image_id} is not exist")
        try:
            db.query(models.ImezyUpdateDB).filter(models.ImezyUpdateDB.id == image_id).delete()
            db.commit()
        except Exception as e:
            print_message(e)
            db.rollback()
            print_message(f"Delete image user: {auth['email']}, image_id: {image_id} failed")
            return HTTPException(status_code=404, detail=f"Delete image user: {auth['email']}, image_id: {image_id} failed")
        
        print_message(f"Delete image user: {auth['email']}, image_id: {image_id} success")
        return {"detail": f"Delete image user: {auth['email']}, image_id: {image_id} success"}
        
    def download_image(self, image_id: int, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db), req: DownloadImageRequest = Depends()):
        authenticated_access_token_check(auth)
        print_message(f"Download image user: {auth['email']}, image_id: {image_id}")
        
        image_db = db.query(models.ImezyUpdateDB).filter(models.ImezyUpdateDB.id == image_id).first()
        if image_db is None:
            return HTTPException(status_code=404, detail=f"Download image user: {auth['email']}, image_id: {image_id} is not exist on db")
        elif image_db.email != auth['email']:
            return exceptions.get_inappropriate_user_exception()
        
        image_type =IMEZY_CONFIG['imezy_type1'][str(image_db.imezy_type)]
        image_updated = datetime.strptime(str(image_db.updated), "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d%H%M%S")
        try:
            with open(f"generated/{image_type}/{auth['email']}/{image_updated}.json", "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            return HTTPException(status_code=404, detail=f"Download image user: {auth['email']}, image_id: {image_id} {image_updated}.json is not exist on file")
            
        if data["images"]:
            return {"image_id": image_id, "updated": image_db.updated, "index": req.index, "image": data["images"][req.index]}
        
    def email_verification_send(self, req: EmailVerificaionSendRequest, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        print_message(f"Verify email: {auth['email']} create code")
        print(req.email_to)
        from random import randint
        code = randint(100000, 999999)

        if req.email_to != "": # 특정 이메일로 보내는 경우
            email_to = req.email_to
            email_to_username = db.query(models.UsersDB).filter(models.UsersDB.email == auth["email"]).first().username            
            verify_email_db = models.VerifyEmailChangeDB(email_from=auth["email"], email_to=email_to, code=code)
            db.add(verify_email_db)
            db.commit()
        else: # 자신의 이메일로 보내는 경우
            email_to = auth["email"]
            email_to_username = db.query(models.UsersDB).filter(models.UsersDB.email == email_to).first().username
            if (verify_email_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == auth["email"]).first()) is None: # 인증코드가 발급되지 않은 경우
                verify_email_db = models.VerifyEmailDB(email=auth["email"], code=code)
            
                db.add(verify_email_db)
                db.commit()
            else: # 이미 인증코드가 발급된 경우
                verify_email_db.code = code
                verify_email_db.updated = datetime.now()
                db.commit()
        
        # subject = "Imezy 이메일 인증 코드"
        subject = "Imezy Email Verification Code"
        with open(settings.VERIFICATION_MAIL_HTML_PATH, "r") as f:
            content = f.read()\
                .replace("{{code}}", str(code))\
                .replace("{{username}}", email_to_username)\
                .replace("{{logo}}", settings.IMEZY_LOGO_250)
        
        result = api_utils.send_email(email_to, subject, content)
        print_message(result["detail"])
        if result["status"] == "success":
            return result
        elif result["status"] == "fail":
            db.delete(verify_email_db)
            db.commit()
            raise HTTPException(status_code=500, detail=result["detail"])    
            
        
        return {"detail": f"Sended 6-digits code to {email_to}"}
    
    def email_verification_check(self, req: EmailVerificationCheckRequest, db: Session = Depends(get_db)):
        print_message(f"Check code: {req.email_to}")
        expire_seconds = req.expires
        
        # db 불러오기
        if (verify_email_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == req.email_to).first()) is None:
            return HTTPException(status_code=404, detail=f"User {req.email_to} is not exist")
        
        print_message(f"Correct code: {verify_email_db.code}, req code: {req.code}") # 코드 일치 여부 확인
        
        # 만료 여부 확인
        now = datetime.now().replace(microsecond=0)
        total_sec = (now - verify_email_db.updated).total_seconds()
        print_message(f"datetime.now: {now}, updated: {verify_email_db.updated}, total_seconds: {total_sec}")
        if (datetime.now() - verify_email_db.updated).total_seconds() > expire_seconds:
            print_message(f"Code is expired")
            raise exceptions.code_exception_exception(0)
        # 코드 일치 여부 확인
        elif int(verify_email_db.code) != int(req.code):
            print_message(f"Code is not correct")
            raise exceptions.code_exception_exception(1)
        
        verify_email_db.verified = True
        db.commit()
        
        return {"detail": f"Code is correct"}
    
    def email_verification_change_check(self, req: EmailVerificationCheckRequest, db: Session = Depends(get_db)):
        print_message(f"Check code: {req.email_to}")
        expire_seconds = req.expires
        
        # db 불러오기
        if (result := db.query(models.VerifyEmailChangeDB).filter(models.VerifyEmailChangeDB.email_to == req.email_to).all()) is None:
            return HTTPException(status_code=404, detail=f"User {req.email_to} is not exist")
        verify_email_db = result[-1]
        print_message(f"Correct code: {verify_email_db.code}, req code: {req.code}")
        
        # 만료 여부 확인
        now = datetime.now().replace(microsecond=0)
        total_sec = (now - verify_email_db.updated).total_seconds()
        print_message(f"datetime.now: {now}, updated: {verify_email_db.updated}, total_seconds: {total_sec}")
        if (datetime.now() - verify_email_db.updated).total_seconds() > expire_seconds:
            print_message(f"Code is expired")
            raise exceptions.code_exception_exception(0)
        # 코드 일치 여부 확인
        elif int(verify_email_db.code) != int(req.code):
            print_message(f"Code is not correct")
            raise exceptions.code_exception_exception(1)
        
        return {"status": "success", "detail": f"Code is correct"}
        
    def feedback_email_send(self, req: FeedbackEmailRequest, db: Session = Depends(get_db)):
        print_message(f"Send feedback email: {req.email}")
        
        feedback_type = IMEZY_CONFIG['feedback_type'][str(req.type)]
        subject = req.subject
        content = f"Feedback type: {feedback_type}\n\nSent from: {req.email}\n\n{req.content}"
        email = req.email
        
        api_utils.send_email(IMEZY_CONFIG["admin_email"], subject, content)
        
        return {"detail": f"Sended feedback email to {email}"}
        
    
    def update_email(self, req: UpdateEmailRequest, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        print_message(f"Update email user: {auth['email']}")
        print_message(f"req email: {req.email}, req confirm_email: {req.confirm_email}")
        if req.email != req.confirm_email:
            raise HTTPException(status_code=400, detail="Emails do not match")
        elif db.query(models.UsersDB).filter(models.UsersDB.email == req.email).first():
            raise HTTPException(status_code=400, detail="Email already exists")
        
        current_email = auth['email']
        user_db = db.query(models.UsersDB).filter(models.UsersDB.email == current_email).first()
        if user_db is None:
            print_message(f"The token is invalid({current_email}). Please login again.")
            raise HTTPException(status_code=401, detail=f"The token is invalid({current_email}). Please login again.")
        user_db.email = req.email
        db.commit()
        
        if (verify_email_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == current_email).first()) is None:
            verified = False
        else:
            verified = verify_email_db.verified
            
        try:
            access_token = create_access_token(email=user_db.email, user_id=auth["user_id"], verified=verified)
            refresh_token = create_refresh_token(email=user_db.email, user_id=auth["user_id"])
            response = {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
            response.update({"message": "Email updated to '{}' successfully".format(req.email)})
        except:
            db.rollback()
            raise HTTPException(status_code=500, detail="Could not update email")

        return response
    
    def update_username(self, req: UpdateUsernameRequest, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        if db.query(models.UsersDB).filter(models.UsersDB.username == req.username).first():
            raise HTTPException(status_code=400, detail="Username already exists")
        elif len(req.username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")
        
        user_info = db.query(models.UsersDB).filter(models.UsersDB.id == auth["user_id"]).first()
        if not user_info:
            raise exceptions.get_user_not_found_exception()
        
        user_info.username = req.username
        try:
            db.commit()
            print_message(f"Username updated to {req.username} successfully")
            return {"message": "Username updated to '{}' successfully".format(req.username)}
        except AttributeError:
            db.rollback()
            raise HTTPException(status_code=500, detail="Could not update username")
    
    def delete_user_by_id(self, user_id: int, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        
        authenticated_access_token_check(auth)
        if db.query(models.UsersDB).filter(models.UsersDB.email == auth["email"]).first().is_admin == False:
            print_message("User is not admin")
            raise exceptions.get_admin_exception()
        
        user_db = db.query(models.UsersDB).filter(models.UsersDB.id == user_id).first()
        username = user_db.username
        credits_info = db.query(models.CreditsDB).filter(models.CreditsDB.email == user_db.email).first()
        if user_db is not None:
            db.delete(credits_info)
            db.delete(user_db)
            db.commit()
            print_message(f"User {user_id}:{username} deleted")
            return {"message": f"User {user_id}:{username} deleted"}
        raise exceptions.get_user_not_found_exception()
    
    def user_update_history(self, user: dict, db: Session = Depends(get_db)):
        user_info = db.query(models.UsersDB).filter(models.UsersDB.email == user["email"]).first()
        user_info.last_login = datetime.datetime.now()
        db.commit()

    def update_user_by_id(self, user_id: int, user: UpdateUserRequest, db: Session = Depends(get_db)):
        return update_user(db, user_id, user)

    def read_all_users(self, db: Session = Depends(get_db)):
        return read_users(db)

    def read_user_by_id(self, user_id: int, 
                        user: dict = Depends(access_token_auth),
                        db: Session = Depends(get_db)):
        authenticated_access_token_check(user)
        user_info = db.query(models.UsersDB).filter(models.UsersDB.id == user_id).first()
        if user_info is not None:
            return user_info
        raise exceptions.get_user_not_found_exception()

    def read_user_info(self, user: dict = Depends(access_token_auth),
                         db: Session = Depends(get_db)):
        authenticated_access_token_check(user)
        
        try:
            user_info = db.query(models.UsersDB).filter(models.UsersDB.email == user["email"]).first().__dict__
        except AttributeError:
            raise HTTPException(status_code=404, detail=f"User not found with email {user['email']}")
        
        del user_info['hashed_password'], user_info['is_admin'], user_info['_sa_instance_state']
        
        
        credits_db= db.query(models.CreditsDB).filter(models.CreditsDB.email == user_info["email"]).first()
        if credits_db is None:
            user_info['credits'] = 0
        else:
            user_info['credits'] = credits_db.credits
            
        if (verified_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == user_info["email"]).first()) is None:
            user_info['verified'] = False
        else:
            user_info['verified'] = verified_db.verified
        print_message(f'Read user info: {user_info["email"]}')
        return user_info

    def authenticate_user(self, email, password, db):
        user_db = db.query(models.UsersDB)\
            .filter(models.UsersDB.email == email).first()
        
        if not user_db:
            return False
        if not verify_password(password, user_db.hashed_password):
            return False
        return user_db
    
    def login(self, form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: Session = Depends(get_db)):
        print_message(f"Login attempt: {form_data.email}")
        if (user_db := self.authenticate_user(form_data.email, form_data.password, db)) is False:
            raise exceptions.token_exception()
        
        
        if (verify_email_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == user_db.email).first()) is None:
            verified = False
        else:
            verified = verify_email_db.verified
        
        access_token = create_access_token(email=user_db.email, user_id=user_db.id, verified=verified)
        refresh_token = create_refresh_token(email=user_db.email, user_id=user_db.id)
        former_rtoken = db.query(models.RefreshTokenDB).filter(models.RefreshTokenDB.email == user_db.email).first()
        
        # check if user has a refresh token is outdated
        if not former_rtoken:
            new_rtoken = models.RefreshTokenDB()
            new_rtoken.token = refresh_token
            new_rtoken.email = user_db.email
            
            db.add(new_rtoken)
            db.commit()
        else:
            former_rtoken.token = refresh_token
            db.commit()
        
        return {
            "access_token": access_token, 
            "refresh_token": refresh_token, 
            "token_type": "bearer"}
    
    # get new access token with refresh token
    def reissue_access_token(self, db: Session = Depends(get_db), auth: dict = Depends(refresh_token_auth)):
        authenticated_access_token_check(auth)
        
        if (user_db := db.query(models.UsersDB).filter(models.UsersDB.email == auth["email"]).first()) is None:
            raise exceptions.token_exception()
        
        rtoken = db.query(models.RefreshTokenDB).filter(models.RefreshTokenDB.email == user_db.email).first()
        if not rtoken:
            raise exceptions.token_exception()
        
        if (verify_email_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == auth["email"]).first()) is None:
            verified = False
        else:
            verified = verify_email_db.verified
        
        access_token = create_access_token(email=user_db.email, user_id=user_db.id, verified=verified)
        return {
            "access_token": access_token, 
            "token_type": "bearer"}
    
    # when user logs out, delete refresh token
    def logout(self, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        
        if (rtoken := db.query(models.RefreshTokenDB).filter(models.RefreshTokenDB.email == auth["email"]).first()) is None:
            raise exceptions.token_exception()
        
        db.delete(rtoken)
        db.commit()
        return {"message": f"user {auth['email']} logged out"}
    
    def login_new(self, user: UserResponse, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth)
        if (user_db := db.query(models.UsersDB).filter(models.UsersDB.email == user.email).first()) is None:
            raise exceptions.get_user_not_found_exception()
        elif not verify_password(user.password, user_db.hashed_password):
            raise exceptions.get_incorrent_password_exception
        elif not user_db.is_active:
            raise exceptions.get_not_active_user_exception()
        
        
        if (verify_email_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == auth['email']).first()) is None:
            verified = False
        else:
            verified = verify_email_db.verified
            
        access_token = auth.create_access_token(subject=user.email, user_id=user_db.id, verified=verified)
        refresh_token = auth.create_refresh_token(subject=user.email, user_id=user_db.id)
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    def update_password(self, user: UpdatePasswordRequest, db: Session = Depends(get_db), auth: dict = Depends(access_token_auth)):
        if not auth:
            raise exceptions.get_user_exception()
        if auth["email"] != user.email:
            raise HTTPException(status_code=401, detail="Unauthorized user. Incorrect email")
        print_message(f"Updating password for user: {user.email}")
        
        if user.new_password != user.confirm_password:
            raise HTTPException(status_code=400, detail="New password and confirm password do not match")
        elif not update_password(db, user): # update_password returns True if password was updated. it updates the password it self
            raise HTTPException(status_code=400, detail="Incorrect old password")
        
        info = f"Password updated successfully for user: {user.email}"
        print_message(info)
        return UpdatePasswordResponse(info=info)

    def create_new_user(self, create_user: CreateUserResponse, db: Session = Depends(get_db)):
        # filter if create_user.email or create_user.username already exists
        print_message(f"Creating a new user. email: {create_user.email}, username: {create_user.username}")
        
        is_exist = []
        is_exist.append(db.query(models.UsersDB).filter(models.UsersDB.username == create_user.username).first())
        is_exist.append(db.query(models.UsersDB).filter(models.UsersDB.email == create_user.email.lower()).first())
        if is_exist[0]:
            print_message(f"The username '{create_user.username}' is already in use")
            raise HTTPException(status_code=400, detail=f"username", headers={"username": create_user.username})
        elif is_exist[1]:
            print_message(f"The email {create_user.email} is already in use")
            raise HTTPException(status_code=400, detail=f"email", headers={"email": create_user.email})
        
        create_user_model = models.UsersDB()
        create_user_model.email = create_user.email.lower()
        create_user_model.username = create_user.username
        create_user_model.is_active = create_user.is_active
        create_user_model.hashed_password = get_password_hashed(create_user.password)
        create_user_model.is_admin = create_user.is_admin
        print_message(f"Creating user: {create_user_model.email}, {create_user_model.username}")
        db.add(create_user_model)
        
        try:
            db.commit()
            print_message(f'User {create_user_model.email} created successfully')
            if create_user.is_admin:
                add_admin = models.UsersAdminDB()
                add_admin.email = create_user.email.lower()
                db.add(add_admin)
                db.commit()
        except exc.IntegrityError:
            db.rollback()
            print_message("User already exist")
            raise HTTPException(status_code=400, detail=f"The user {create_user_model.email} already exist")
        except FlushError:
            db.rollback()
            print_message(f"User already exist")
            raise HTTPException(status_code=400, detail=f"The user {create_user_model.email} already exist")
        
        
        new_credit = models.CreditsDB()
        new_credit.email = create_user_model.email
        db.add(new_credit)
        
        try:
            db.commit()
            print_message(f'Credits for user {create_user_model.email} created successfully')
        except exc.IntegrityError:
            db.rollback()
            db.query(models.UsersDB).filter(models.UsersDB.email == create_user_model.email).delete()
            db.commit()
            print_message(f"Failed to create credits for the user {create_user_model.email}")
            raise HTTPException(status_code=400, detail=f"Failed to create credits for the user {create_user_model.email}")
        except FlushError:
            db.rollback()
            db.query(models.UsersDB).filter(models.UsersDB.email == create_user_model.email).delete()
            db.commit()
            print_message(f"Failed to create credits for the user {create_user_model.email}")
            raise HTTPException(status_code=400, detail=f"Failed to create credits for the user {create_user_model.email}")

        return {"message": f"User {create_user.username} created successfully"}
    
    # def update_credits(self, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
    #     if not auth:
    #         raise exceptions.get_user_exception()
    #     print_message(f"Updating credits for user {auth['email']}")
        
    #     user = db.query(models.UsersDB).filter(models.UsersDB.email == auth["email"]).first()
    #     if user is None:
    #         raise exceptions.get_user_exception()
    #     user_credits = db.query(models.CreditsDB).filter(models.CreditsDB.user_id == user.id).first()
    #     if user_credits is None:
    #         raise exceptions.get_user_exception()
    #     user_credits.credits = user_credits.credits + user_credits.credits_inc
    #     db.commit()
    #     return {"message": f"Credits updated for user {user.username}"}
    
    def make_admin(self, user_id: int, user: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(user)
        if db.query(models.UsersDB).filter(models.UsersDB.email == user["email"]).first().is_admin == False:
            print_message("User is not admin")
            raise exceptions.get_admin_exception()
        
        user_info = db.query(models.UsersDB).filter(models.UsersDB.id == user_id).first()
        if user_info is not None:
            user_info.is_admin = True
            db.commit()
            print_message(f"User {user_id}:{user_info.username} is now admin")
            return {"message": f"User {user_id}:{user_info.username} is now admin"}
        raise HTTPException(status_code=404, detail="User not found")
    
    def add_api_route(self, path: str, endpoint, **kwargs):
        if shared.cmd_opts.api_auth:
            return self.app.add_api_route(path, endpoint, dependencies=[Depends(self.auth)], **kwargs)
        return self.app.add_api_route(path, endpoint, **kwargs)

    def auth(self, credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
        if credentials.username in self.credentials:
            if compare_digest(credentials.password, self.credentials[credentials.username]):
                return True

        raise HTTPException(status_code=401, detail="Incorrect username or password", headers={"WWW-Authenticate": "Basic"})

    def text2imgapi(self, txt2imgreq: StableDiffusionTxt2ImgProcessingAPI):
        populate = txt2imgreq.copy(update={ # Override __init__ params
            "sampler_name": validate_sampler_name(txt2imgreq.sampler_name or txt2imgreq.sampler_index),
            "do_not_save_samples": True,
            "do_not_save_grid": True
            }
        )
        if populate.sampler_name:
            populate.sampler_index = None  # prevent a warning later on

        with self.queue_lock:
            p = StableDiffusionProcessingTxt2Img(sd_model=shared.sd_model, **vars(populate))

            shared.state.begin()
            processed = process_images(p)
            shared.state.end()


        b64images = list(map(encode_pil_to_base64, processed.images))
        b64images_compressed = list(map(convert_img_to_webp, processed.images))

        return TextToImageResponse(images=b64images, images_compressed=b64images_compressed, parameters=vars(txt2imgreq), info=json.loads(processed.js()))

    def text2imgapi_auth(self, txt2imgreq: StableDiffusionTxt2ImgProcessingAPI, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth, db=db, verify=True)
        print_message(f"User {auth['email']} is generating images txt2imgapi_auth")
        # check auth email and if the user has enough credits
        
        user_db = db.query(models.CreditsDB).filter(models.CreditsDB.email == auth["email"]).first()
        if user_db is None:
            print_message("user is None exception")
            raise exceptions.get_user_exception()
        created_images_num = int(txt2imgreq.n_iter * txt2imgreq.batch_size)
        
        # 유저가 가진 크레딧이 생성할 이미지의 크레딧보다 적으면 에러
        if user_db.credits < created_images_num * CREDITS_PER_IMAGE:
            raise exceptions.not_enough_credits_exception()
        
        response = self.text2imgapi(txt2imgreq)
        response_json = json.loads(response.json())
        
        # 이미지 압축 저장 to webp
        response_images = response_json["images"]
        
        
        # 이미지 생성 저장(json)
        now = datetime.now().strftime('%Y%m%d%H%M%S')
        if os.path.exists(f"generated/t2i/{auth['email']}") == False:
            os.makedirs(f"generated/t2i/{auth['email']}")
            
        with open(f"generated/t2i/{auth['email']}/{now}.json", "w") as f:
            json.dump(response_json, f, indent=4)
        
        # 이미지 생성 데이터베이스 기록
        imezy_update_db = models.ImezyUpdateDB()
        imezy_update_db.email = auth['email']
        imezy_update_db.imezy_type = IMEZY_CONFIG["imezy_type"]['t2i']
        imezy_update_db.num_imgs = created_images_num
        imezy_update_db.updated = now
        db.add(imezy_update_db)

        # 크레딧 업데이트
        updateing_credit_inc = -created_images_num *CREDITS_PER_IMAGE # 이미지당 10크레딧 차감
        if credits.update_cred(user_db.email, updateing_credit_inc, db) == -1:
            print_message(f"{auth['email']}'s update_cred failed")
            raise exceptions.get_user_exception()
        
        print_message(f"User {auth['email']} is generating an image. Credits left: {user_db.credits}, Credits used: {-updateing_credit_inc}, generated images: {created_images_num}")
        
        response = TextToImageAuthResponse(images=response_images, images_compressed=response_json["images_compressed"], 
                                             parameters=response_json["parameters"], info=response_json["info"], 
                                             credits=user_db.credits)

        return response

    def img2imgapi(self, img2imgreq: StableDiffusionImg2ImgProcessingAPI):
        init_images = img2imgreq.init_images
        if init_images is None:
            raise HTTPException(status_code=404, detail="Init image not found")

        mask = img2imgreq.mask
        if mask:
            print_message(mask[:100])
            mask = decode_base64_to_image(mask)

        populate = img2imgreq.copy(update={ # Override __init__ params
            "sampler_name": validate_sampler_name(img2imgreq.sampler_name or img2imgreq.sampler_index),
            "do_not_save_samples": True,
            "do_not_save_grid": True,
            "mask": mask
            }
        )
        if populate.sampler_name:
            populate.sampler_index = None  # prevent a warning later on

        args = vars(populate)
        args.pop('include_init_images', None)  # this is meant to be done by "exclude": True in model, but it's for a reason that I cannot determine.

        with self.queue_lock:
            p = StableDiffusionProcessingImg2Img(sd_model=shared.sd_model, **args)
            p.init_images = [decode_base64_to_image(x) for x in init_images]

            shared.state.begin()
            processed = process_images(p)
            shared.state.end()

        b64images = list(map(encode_pil_to_base64, processed.images))
        b64images_compressed = list(map(convert_img_to_webp, processed.images))

        if not img2imgreq.include_init_images:
            img2imgreq.init_images = None
            img2imgreq.mask = None

        return ImageToImageResponse(images=b64images, images_compressed=b64images_compressed, parameters=vars(img2imgreq), info=json.loads(processed.js()))

    def img2imgapi_auth(self, img2imgreq: StableDiffusionImg2ImgProcessingAPI, 
                        auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth, db=db, verify=True)
        print_message(f"User {auth['email']} is generating an image using img2imgapi_auth")
        
        user_db = db.query(models.CreditsDB).filter(models.CreditsDB.email == auth["email"]).first()
        if user_db is None:
            print_message("user is None exception")
            raise exceptions.get_user_exception()
        created_images_num = int(img2imgreq.n_iter * img2imgreq.batch_size)
        
        # 유저가 가진 크레딧이 생성할 이미지의 크레딧보다 적으면 에러
        if user_db.credits < created_images_num * CREDITS_PER_IMAGE:
            raise exceptions.not_enough_credits_exception()
        
        response = self.img2imgapi(img2imgreq)
        response_json = json.loads(response.json())
                    
        # save the response to the database
        now = datetime.now().strftime('%Y%m%d%H%M%S')
        if os.path.exists(f"generated/i2i/{auth['email']}") == False:
            os.makedirs(f"generated/i2i/{auth['email']}")
        with open(f"generated/i2i/{auth['email']}/{now}.json", "w") as f:
            json.dump(response_json, f, indent=4)
            
        # 이미지 생성 데이터베이스 기록
        imezy_update_db = models.ImezyUpdateDB()
        imezy_update_db.email = auth['email']
        imezy_update_db.imezy_type = IMEZY_CONFIG["imezy_type"]['i2i']
        imezy_update_db.num_imgs = created_images_num
        imezy_update_db.updated = now
        db.add(imezy_update_db)

        # update credits
        updateing_creedit_inc = -created_images_num*CREDITS_PER_IMAGE # 10 credits per image
        if credits.update_cred(user_db.email, updateing_creedit_inc, db) == False:
            raise exceptions.get_user_exception()
        
        print_message(f"User {auth['email']} is generating an image. Credits left: {user_db.credits}, Credits used: {-updateing_creedit_inc}, generated images: {created_images_num}")
        
        response = ImageToImageAuthResponse(images=response_json["images"], images_compressed=response_json["images_compressed"], 
                                            parameters=response_json["parameters"], info=response_json["info"], 
                                            credits=user_db.credits)
        
        return response

    def extras_single_image_api(self, req: ExtrasSingleImageRequest):
        reqDict = setUpscalers(req)

        reqDict['image'] = decode_base64_to_image(reqDict['image'])

        with self.queue_lock:
            result = postprocessing.run_extras(extras_mode=0, image_folder="", input_dir="", output_dir="", save_output=False, **reqDict)

        return ExtrasSingleImageResponse(images=[encode_pil_to_base64(result[0][0])], html_info=result[1])
    
    def extras_single_image_api_auth(self, req: ExtrasSingleImageRequest, 
                                     auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        authenticated_access_token_check(auth, db=db, verify=True)
        
        response = self.extras_single_image_api(req)
        
        return response

    def extras_batch_images_api(self, req: ExtrasBatchImagesRequest):
        reqDict = setUpscalers(req)

        def prepareFiles(file):
            file = decode_base64_to_file(file.data, file_path=file.name)
            file.orig_name = file.name
            return file

        reqDict['image_folder'] = list(map(prepareFiles, reqDict['imageList']))
        reqDict.pop('imageList')

        with self.queue_lock:
            result = postprocessing.run_extras(extras_mode=1, image="", input_dir="", output_dir="", save_output=False, **reqDict)

        return ExtrasBatchImagesResponse(images=list(map(encode_pil_to_base64, result[0])), html_info=result[1])

    def pnginfoapi(self, req: PNGInfoRequest):
        if(not req.image.strip()):
            return PNGInfoResponse(info="")

        result = run_pnginfo(decode_base64_to_image(req.image.strip()))

        return PNGInfoResponse(info=result[1])

    def progressapi(self, req: ProgressRequest = Depends()):
        # copy from check_progress_call of ui.py

        if shared.state.job_count == 0:
            return ProgressResponse(progress=0, eta_relative=0, state=shared.state.dict(), textinfo=shared.state.textinfo)

        # avoid dividing zero
        progress = 0.01

        if shared.state.job_count > 0:
            progress += shared.state.job_no / shared.state.job_count
        if shared.state.sampling_steps > 0:
            progress += 1 / shared.state.job_count * shared.state.sampling_step / shared.state.sampling_steps

        time_since_start = time.time() - shared.state.time_start
        eta = (time_since_start/progress)
        eta_relative = eta-time_since_start

        progress = min(progress, 1)

        shared.state.set_current_image()

        current_image = None
        if shared.state.current_image and not req.skip_current_image:
            current_image = encode_pil_to_base64(shared.state.current_image)

        return ProgressResponse(progress=progress, eta_relative=eta_relative, state=shared.state.dict(), current_image=current_image, textinfo=shared.state.textinfo)

    def interrogateapi(self, interrogatereq: InterrogateRequest):
        image_b64 = interrogatereq.image
        if image_b64 is None:
            raise HTTPException(status_code=404, detail="Image not found")

        img = decode_base64_to_image(image_b64)
        img = img.convert('RGB')

        # Override object param
        with self.queue_lock:
            if interrogatereq.model == "clip":
                processed = shared.interrogator.interrogate(img)
            elif interrogatereq.model == "deepdanbooru":
                processed = deepbooru.model.tag(img)
            else:
                raise HTTPException(status_code=404, detail="Model not found")

        return InterrogateResponse(caption=processed)

    def interruptapi(self):
        shared.state.interrupt()

        return {}

    def skip(self):
        shared.state.skip()

    def get_config(self):
        options = {}
        for key in shared.opts.data.keys():
            metadata = shared.opts.data_labels.get(key)
            if(metadata is not None):
                options.update({key: shared.opts.data.get(key, shared.opts.data_labels.get(key).default)})
            else:
                options.update({key: shared.opts.data.get(key, None)})

        return options

    def set_config(self, req: Dict[str, Any]):
        for k, v in req.items():
            shared.opts.set(k, v)

        shared.opts.save(shared.config_filename)
        return

    def get_cmd_flags(self):
        return vars(shared.cmd_opts)

    def get_samplers(self):
        return [{"name": sampler[0], "aliases":sampler[2], "options":sampler[3]} for sampler in sd_samplers.all_samplers]

    def get_upscalers(self):
        return [
            {
                "name": upscaler.name,
                "model_name": upscaler.scaler.model_name,
                "model_path": upscaler.data_path,
                "model_url": None,
                "scale": upscaler.scale,
            }
            for upscaler in shared.sd_upscalers
        ]

    def get_sd_models(self):
        return [{"title": x.title, "model_name": x.model_name, "hash": x.shorthash, "sha256": x.sha256, "filename": x.filename, "config": find_checkpoint_config_near_filename(x)} for x in checkpoints_list.values()]

    def get_hypernetworks(self):
        return [{"name": name, "path": shared.hypernetworks[name]} for name in shared.hypernetworks]

    def get_face_restorers(self):
        return [{"name":x.name(), "cmd_dir": getattr(x, "cmd_dir", None)} for x in shared.face_restorers]

    def get_realesrgan_models(self):
        return [{"name":x.name,"path":x.data_path, "scale":x.scale} for x in get_realesrgan_models(None)]

    def get_prompt_styles(self):
        styleList = []
        for k in shared.prompt_styles.styles:
            style = shared.prompt_styles.styles[k]
            styleList.append({"name":style[0], "prompt": style[1], "negative_prompt": style[2]})

        return styleList

    def get_embeddings(self):
        db = sd_hijack.model_hijack.embedding_db

        def convert_embedding(embedding):
            return {
                "step": embedding.step,
                "sd_checkpoint": embedding.sd_checkpoint,
                "sd_checkpoint_name": embedding.sd_checkpoint_name,
                "shape": embedding.shape,
                "vectors": embedding.vectors,
            }

        def convert_embeddings(embeddings):
            return {embedding.name: convert_embedding(embedding) for embedding in embeddings.values()}

        return {
            "loaded": convert_embeddings(db.word_embeddings),
            "skipped": convert_embeddings(db.skipped_embeddings),
        }

    def refresh_checkpoints(self):
        shared.refresh_checkpoints()

    def create_embedding(self, args: dict):
        try:
            shared.state.begin()
            filename = create_embedding(**args) # create empty embedding
            sd_hijack.model_hijack.embedding_db.load_textual_inversion_embeddings() # reload embeddings so new one can be immediately used
            shared.state.end()
            return CreateResponse(info = "create embedding filename: {filename}".format(filename = filename))
        except AssertionError as e:
            shared.state.end()
            return TrainResponse(info = "create embedding error: {error}".format(error = e))

    def create_hypernetwork(self, args: dict):
        try:
            shared.state.begin()
            filename = create_hypernetwork(**args) # create empty embedding
            shared.state.end()
            return CreateResponse(info = "create hypernetwork filename: {filename}".format(filename = filename))
        except AssertionError as e:
            shared.state.end()
            return TrainResponse(info = "create hypernetwork error: {error}".format(error = e))

    def preprocess(self, args: dict):
        try:
            shared.state.begin()
            preprocess(**args) # quick operation unless blip/booru interrogation is enabled
            shared.state.end()
            return PreprocessResponse(info = 'preprocess complete')
        except KeyError as e:
            shared.state.end()
            return PreprocessResponse(info = "preprocess error: invalid token: {error}".format(error = e))
        except AssertionError as e:
            shared.state.end()
            return PreprocessResponse(info = "preprocess error: {error}".format(error = e))
        except FileNotFoundError as e:
            shared.state.end()
            return PreprocessResponse(info = 'preprocess error: {error}'.format(error = e))

    def train_embedding(self, args: dict):
        try:
            shared.state.begin()
            apply_optimizations = shared.opts.training_xattention_optimizations
            error = None
            filename = ''
            if not apply_optimizations:
                sd_hijack.undo_optimizations()
            try:
                embedding, filename = train_embedding(**args) # can take a long time to complete
            except Exception as e:
                error = e
            finally:
                if not apply_optimizations:
                    sd_hijack.apply_optimizations()
                shared.state.end()
            return TrainResponse(info = "train embedding complete: filename: {filename} error: {error}".format(filename = filename, error = error))
        except AssertionError as msg:
            shared.state.end()
            return TrainResponse(info = "train embedding error: {msg}".format(msg = msg))

    def train_hypernetwork(self, args: dict):
        try:
            shared.state.begin()
            shared.loaded_hypernetworks = []
            apply_optimizations = shared.opts.training_xattention_optimizations
            error = None
            filename = ''
            if not apply_optimizations:
                sd_hijack.undo_optimizations()
            try:
                hypernetwork, filename = train_hypernetwork(*args)
            except Exception as e:
                error = e
            finally:
                shared.sd_model.cond_stage_model.to(devices.device)
                shared.sd_model.first_stage_model.to(devices.device)
                if not apply_optimizations:
                    sd_hijack.apply_optimizations()
                shared.state.end()
            return TrainResponse(info="train embedding complete: filename: {filename} error: {error}".format(filename=filename, error=error))
        except AssertionError as msg:
            shared.state.end()
            return TrainResponse(info="train embedding error: {error}".format(error=error))

    def get_memory(self):
        try:
            import os, psutil
            process = psutil.Process(os.getpid())
            res = process.memory_info() # only rss is cross-platform guaranteed so we dont rely on other values
            ram_total = 100 * res.rss / process.memory_percent() # and total memory is calculated as actual value is not cross-platform safe
            ram = { 'free': ram_total - res.rss, 'used': res.rss, 'total': ram_total }
        except Exception as err:
            ram = { 'error': f'{err}' }
        try:
            import torch
            if torch.cuda.is_available():
                s = torch.cuda.mem_get_info()
                system = { 'free': s[0], 'used': s[1] - s[0], 'total': s[1] }
                s = dict(torch.cuda.memory_stats(shared.device))
                allocated = { 'current': s['allocated_bytes.all.current'], 'peak': s['allocated_bytes.all.peak'] }
                reserved = { 'current': s['reserved_bytes.all.current'], 'peak': s['reserved_bytes.all.peak'] }
                active = { 'current': s['active_bytes.all.current'], 'peak': s['active_bytes.all.peak'] }
                inactive = { 'current': s['inactive_split_bytes.all.current'], 'peak': s['inactive_split_bytes.all.peak'] }
                warnings = { 'retries': s['num_alloc_retries'], 'oom': s['num_ooms'] }
                cuda = {
                    'system': system,
                    'active': active,
                    'allocated': allocated,
                    'reserved': reserved,
                    'inactive': inactive,
                    'events': warnings,
                }
            else:
                cuda = { 'error': 'unavailable' }
        except Exception as err:
            cuda = { 'error': f'{err}' }
        return MemoryResponse(ram = ram, cuda = cuda)

    def launch(self, server_name, port):
        self.app.include_router(self.router)
        uvicorn.run(self.app, host=server_name, port=port)

    def read_all_creds(self, db: Session = Depends(get_db)):
        return credits.read_creds(db)
    
    def read_cred_by_id(self, user: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        if user['type'] == 'refresh':
            return self.reissue_access_token(db=db, auth=user)
        
        authenticated_access_token_check(user)
        user_email = user.get("email", None)
        return credits.read_creds(db, user_email)
    
    
    def update_cred(self, req: UpdateCreditsRequest, auth: dict = Depends(access_token_auth), db: Session = Depends(get_db)):
        if auth['type'] == 'refresh':
            return self.reissue_access_token(db=db, auth=auth)
        print_message(f"Updating credits. access user email: {auth.get('email', None)}, inc: {req.credits_inc}, target user email: {req.email}")
        
        req = req.dict()
        user_admin_db = db.query(models.UsersAdminDB).filter(models.UsersAdminDB.email == auth.get("email", None)).first()
        
        # if the user is not admin, he can only update his own credits
        if user_admin_db != None or req['email'] == auth['email']:
            print_message("User is admin or updating his own credits")
            current_credits = credits.update_cred(req["email"], req["credits_inc"], db)
            return UpdateCreditsResponse(info = "Credits updated", email=req['email'], credits_inc=req['credits_inc'], currunt_credits=current_credits)
        else:
            raise HTTPException(status_code=403, detail="You are not authorized to update credits for this user")
    
    def modifiers_read(self, db: Session = Depends(get_db), modifier: int = None):
        '''
        modifier starts from 1
        modifier: None - return all modifier categories
        modifier: 0 - return all modifiers
        modifier: 1, ..., n - return all modifiers in category n
        '''
        print_message(f"Reading modifiers. modifier: {modifier}")
        modifier_len = len(db.query(models.ModifiersClassDB).all())
        if modifier == None:
            response = styles.read_modifier(db)
            return response
        elif (type(modifier) is not int) or (modifier < -1 or modifier > modifier_len):
            raise HTTPException(status_code=400, detail=f"Invalid modifier id, must be an integer(0 <= id <= {modifier_len}).  0 - return all modifiers. 1, ..., n - return all modifiers in category n")
        response = styles.read_modifier(db, modifier)
    
        return response
    
    def styles_read(self, db: Session = Depends(get_db)):
        print_message("Reading styles")
        response = styles.read_styles(db)
        return response