import base64
import io
import time
import uvicorn
from threading import Lock
from io import BytesIO
from gradio.processing_utils import decode_base64_to_file
from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordRequestForm, OAuth2PasswordBearer
from secrets import compare_digest
from datetime import datetime, timedelta

import modules.shared as shared
from modules import sd_samplers, deepbooru
from modules.api.models import *
from modules.processing import StableDiffusionProcessingTxt2Img, StableDiffusionProcessingImg2Img, process_images
from modules.extras import run_extras, run_pnginfo
from PIL import PngImagePlugin,Image
from modules.sd_models import checkpoints_list
from modules.realesrgan_model import get_realesrgan_models
from typing import List

from passlib.context import CryptContext
from .database import engine, SessionLocal
from sqlalchemy.orm import Session
import sqlalchemy.exc as exc
from . import models

# auth
from jose import JWTError, jwt
from .auth import get_current_user, get_user_exception, oauth2_bearer

SECRET_KEY = "secret_api_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

models.Base.metadata.create_all(bind=engine)
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")


def upscaler_to_index(name: str):
    try:
        return [x.name.lower() for x in shared.sd_upscalers].index(name.lower())
    except:
        raise HTTPException(status_code=400, detail=f"Invalid upscaler, needs to be on of these: {' , '.join([x.name for x in sd_upscalers])}")


def validate_sampler_name(name):
    config = sd_samplers.all_samplers_map.get(name, None)
    if config is None:
        raise HTTPException(status_code=404, detail="Sampler not found")

    return name

def setUpscalers(req: dict):
    reqDict = vars(req)
    reqDict['extras_upscaler_1'] = upscaler_to_index(req.upscaler_1)
    reqDict['extras_upscaler_2'] = upscaler_to_index(req.upscaler_2)
    reqDict.pop('upscaler_1')
    reqDict.pop('upscaler_2')
    return reqDict

def decode_base64_to_image(encoding):
    if encoding.startswith("data:image/"):
        encoding = encoding.split(";")[1].split(",")[1]
    return Image.open(BytesIO(base64.b64decode(encoding)))

def encode_pil_to_base64(image):
    with io.BytesIO() as output_bytes:

        # Copy any text-only metadata
        use_metadata = False
        metadata = PngImagePlugin.PngInfo()
        for key, value in image.info.items():
            if isinstance(key, str) and isinstance(value, str):
                metadata.add_text(key, value)
                use_metadata = True

        image.save(
            output_bytes, "PNG", pnginfo=(metadata if use_metadata else None)
        )
        bytes_data = output_bytes.getvalue()
    return base64.b64encode(bytes_data)

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()
    
class Api:
    def __init__(self, app: FastAPI, queue_lock: Lock):
        if shared.cmd_opts.api_auth:
            self.credenticals = dict()
            for auth in shared.cmd_opts.api_auth.split(","):
                user, password = auth.split(":")
                self.credenticals[user] = password

        self.router = APIRouter()
        self.app = app
        self.queue_lock = queue_lock
        self.add_api_route("/sdapi/v1/txt2img", self.text2imgapi, methods=["POST"], response_model=TextToImageResponse)
        self.add_api_route("/sdapi/v1/img2img", self.img2imgapi, methods=["POST"], response_model=ImageToImageResponse)
        self.add_api_route("/sdapi/v1/extra-single-image", self.extras_single_image_api, methods=["POST"], response_model=ExtrasSingleImageResponse)
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
        self.add_api_route("/sdapi/v1/prompt-styles", self.get_promp_styles, methods=["GET"], response_model=List[PromptStyleItem])
        self.add_api_route("/sdapi/v1/artist-categories", self.get_artists_categories, methods=["GET"], response_model=List[str])
        self.add_api_route("/sdapi/v1/artists", self.get_artists, methods=["GET"], response_model=List[ArtistItem])
        self.add_api_route("/user/create", self.create_new_user, methods=["POST"], response_model=CreateUserResponse)
        self.add_api_route("/user/get_jwt_token", self.login_for_access_token, methods=["POST"])
        self.add_api_route("/user/read_users", self.read_all_by_user, methods=["GET"], response_model=JWTResponse)
        self.add_api_route("/user/{user_id}", self.read_user_by_id, methods=["GET"], response_model=JWTResponse)

    def read_user_by_id(self, user_id: int, 
                        user: dict = Depends(get_current_user),
                        db: Session = Depends(get_db)):
        if user is None:
            raise get_user_exception()
        user_info = db.query(UsersDB).filter(UsersDB.id == user_id).filter(UsersDB.username == user["username"]).first()
        if user_info is not None:
            return user_info
        raise HTTPException(status_code=404, detail="User not found")
        

    def read_all_by_user(self, user: dict = Depends(get_current_user),
                         db: Session = Depends(get_db)):
        if user is None:
            raise self.get_user_exception()
        return db.query(models.UsersDB).filter(models.UsersDB.email == user.email).all()

    def get_password_hash(self, password):
        return bcrypt_context.hash(password)

    def verify_password(self, plain_password, hashed_password):
        return bcrypt_context.verify(plain_password, hashed_password)

    def authenticate_user(self, email, password, db):
        user = db.query(models.UsersDB)\
            .filter(models.UsersDB.email == email).first()
        
        if not user:
            return False
        if not self.verify_password(password, user.hash_password):
            return False
        return user
    
    
    def login_for_access_token(self, form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: Session = Depends(get_db)):
        user = self.authenticate_user(form_data.email, form_data.password, db)
        if not user:
            raise self.token_exception()
        token_expires = timedelta(minutes=20)
        token = self.create_access_token(email=user.email, user_id=user.id, expires_delta=token_expires)
        return {"access_token": token, "token_type": "bearer"}

    def get_current_user(self, token: str = Depends(oauth2_bearer)):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            user_id: int = payload.get("id")
            if username is None or user_id is None:
                raise self.get_user_exception()
            return {"username": username, "user_id": user_id}
        except JWTError:
            raise self.get_user_exception()

    def create_new_user(self, create_user: CreateUserResponse, db: Session = Depends(get_db)):
        create_user_model = models.UsersDB()
        create_user_model.email = create_user.email
        create_user_model.email = create_user.username
        
        hash_password = self.get_password_hash(create_user.password)
        
        create_user_model.hash_password = hash_password
        create_user_model.is_active = True
        print(f"Create user: {create_user_model.email}")
        db.add(create_user_model)
        try:
            db.commit()
        except exc.IntegrityError:
            db.rollback()
            raise HTTPException(status_code=400, detail="User already exist")

        return {"message": f"User {create_user.username} created successfully"}
    
    def create_access_token(self, email: str, user_id: int, 
                            expires_delta: Optional[timedelta] = None):
        to_encode = {"email": email, "user_id": user_id}
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
        
    def token_exception(self):
        token_exception_response = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        return token_exception_response
    
    def add_api_route(self, path: str, endpoint, **kwargs):
        if shared.cmd_opts.api_auth:
            return self.app.add_api_route(path, endpoint, dependencies=[Depends(self.auth)], **kwargs)
        return self.app.add_api_route(path, endpoint, **kwargs)

    def auth(self, credenticals: HTTPBasicCredentials = Depends(HTTPBasic())):
        if credenticals.username in self.credenticals:
            if compare_digest(credenticals.password, self.credenticals[credenticals.username]):
                return True

        raise HTTPException(status_code=401, detail="Incorrect username or password", headers={"WWW-Authenticate": "Basic"})

    def text2imgapi(self, txt2imgreq: StableDiffusionTxt2ImgProcessingAPI):
        populate = txt2imgreq.copy(update={ # Override __init__ params
            "sd_model": shared.sd_model,
            "sampler_name": validate_sampler_name(txt2imgreq.sampler_name or txt2imgreq.sampler_index),
            "do_not_save_samples": True,
            "do_not_save_grid": True
            }
        )
        if populate.sampler_name:
            populate.sampler_index = None  # prevent a warning later on
        p = StableDiffusionProcessingTxt2Img(**vars(populate))
        # Override object param

        shared.state.begin()

        with self.queue_lock:
            processed = process_images(p)

        shared.state.end()

        b64images = list(map(encode_pil_to_base64, processed.images))

        return TextToImageResponse(images=b64images, parameters=vars(txt2imgreq), info=processed.js())

    def img2imgapi(self, img2imgreq: StableDiffusionImg2ImgProcessingAPI):
        init_images = img2imgreq.init_images
        if init_images is None:
            raise HTTPException(status_code=404, detail="Init image not found")

        mask = img2imgreq.mask
        if mask:
            mask = decode_base64_to_image(mask)

        populate = img2imgreq.copy(update={ # Override __init__ params
            "sd_model": shared.sd_model,
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
        p = StableDiffusionProcessingImg2Img(**args)

        imgs = []
        for img in init_images:
            img = decode_base64_to_image(img)
            imgs = [img] * p.batch_size

        p.init_images = imgs

        shared.state.begin()

        with self.queue_lock:
            processed = process_images(p)

        shared.state.end()

        b64images = list(map(encode_pil_to_base64, processed.images))

        if not img2imgreq.include_init_images:
            img2imgreq.init_images = None
            img2imgreq.mask = None

        return ImageToImageResponse(images=b64images, parameters=vars(img2imgreq), info=processed.js())

    def extras_single_image_api(self, req: ExtrasSingleImageRequest):
        reqDict = setUpscalers(req)

        reqDict['image'] = decode_base64_to_image(reqDict['image'])

        with self.queue_lock:
            result = run_extras(extras_mode=0, image_folder="", input_dir="", output_dir="", **reqDict)

        return ExtrasSingleImageResponse(image=encode_pil_to_base64(result[0][0]), html_info=result[1])

    def extras_batch_images_api(self, req: ExtrasBatchImagesRequest):
        reqDict = setUpscalers(req)

        def prepareFiles(file):
            file = decode_base64_to_file(file.data, file_path=file.name)
            file.orig_name = file.name
            return file

        reqDict['image_folder'] = list(map(prepareFiles, reqDict['imageList']))
        reqDict.pop('imageList')

        with self.queue_lock:
            result = run_extras(extras_mode=1, image="", input_dir="", output_dir="", **reqDict)

        return ExtrasBatchImagesResponse(images=list(map(encode_pil_to_base64, result[0])), html_info=result[1])

    def pnginfoapi(self, req: PNGInfoRequest):
        if(not req.image.strip()):
            return PNGInfoResponse(info="")

        result = run_pnginfo(decode_base64_to_image(req.image.strip()))

        return PNGInfoResponse(info=result[1])

    def progressapi(self, req: ProgressRequest = Depends()):
        # copy from check_progress_call of ui.py

        if shared.state.job_count == 0:
            return ProgressResponse(progress=0, eta_relative=0, state=shared.state.dict())

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

        return ProgressResponse(progress=progress, eta_relative=eta_relative, state=shared.state.dict(), current_image=current_image)

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
        upscalers = []

        for upscaler in shared.sd_upscalers:
            u = upscaler.scaler
            upscalers.append({"name":u.name, "model_name":u.model_name, "model_path":u.model_path, "model_url":u.model_url})

        return upscalers

    def get_sd_models(self):
        return [{"title":x.title, "model_name":x.model_name, "hash":x.hash, "filename": x.filename, "config": x.config} for x in checkpoints_list.values()]

    def get_hypernetworks(self):
        return [{"name": name, "path": shared.hypernetworks[name]} for name in shared.hypernetworks]

    def get_face_restorers(self):
        return [{"name":x.name(), "cmd_dir": getattr(x, "cmd_dir", None)} for x in shared.face_restorers]

    def get_realesrgan_models(self):
        return [{"name":x.name,"path":x.data_path, "scale":x.scale} for x in get_realesrgan_models(None)]

    def get_promp_styles(self):
        styleList = []
        for k in shared.prompt_styles.styles:
            style = shared.prompt_styles.styles[k]
            styleList.append({"name":style[0], "prompt": style[1], "negative_prompt": style[2]})

        return styleList

    def get_artists_categories(self):
        return shared.artist_db.cats

    def get_artists(self):
        return [{"name":x[0], "score":x[1], "category":x[2]} for x in shared.artist_db.artists]

    def launch(self, server_name, port):
        self.app.include_router(self.router)
        uvicorn.run(self.app, host=server_name, port=port)
