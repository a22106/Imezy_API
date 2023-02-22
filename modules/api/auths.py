from datetime import datetime, timedelta
from typing import Optional
import requests

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from modules.api import models
from dataclasses import dataclass

from pydantic import ValidationError
from sqlalchemy.orm import Session

# auth
from passlib.context import CryptContext
from jose import JWTError, jwt, ExpiredSignatureError

from . import exceptions, users
from .logs import print_message
from .database import get_db
from .config import settings


SECRET_KEY_ACCESS = settings.JWT_ACCESS_KEY
SECRET_KEY_REFRESH = settings.JWT_REFRESH_KEY
ALGORITHM_ACCESS = "HS256"
ACCESS_TOKEN_EXPIRES = timedelta(hours=settings.JWT_ACCESS_TOKEN_EXPIRE_HOURS) 
REFRESH_TOKEN_EXPIRES = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS) 


oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def access_token_auth(token: str = Depends(oauth2_bearer), user_type = "normal"):
    
    if user_type == "normal":
        try:
            payload = jwt.decode(token, SECRET_KEY_ACCESS, algorithms=[ALGORITHM_ACCESS])
            print(f"email: {payload.get('email')}, user_id: {payload.get('user_id')}, connected")
            t_type: str = payload.get("type")
            
            email: str = payload.get("email")
            user_id: int = payload.get("user_id")
            
            if email is None or user_id is None: # 키가 잘못된 경우
                print("get_current_user: email or user_id is None")
                raise exceptions.get_user_exception()
            
            return {"email": email, "user_id": user_id, "type": t_type} # 토큰이 유효한 경우
        
        except ExpiredSignatureError: # 토큰이 만료된 경우
            print("Access token is expired")
            raise exceptions.access_token_expired_exception()
        
        except JWTError: # 토큰이 유효하지 않은 경우
            print_message("Access token is invalid")
            raise exceptions.get_jwt_exception()
    elif user_type == "kakao":
        url = "https://kapi.kakao.com/v2/user/me" # 카카오 API에서 유저 정보 가져오기
        header = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=header).json()
        try:
            username = response['kakao_account']['profile']['nickname']
            email_kakao = response['kakao_account']['email']
            db = next(get_db())
            email = db.query(models.UsersDB) \
                .filter(models.UsersDB.email_kakao == email_kakao).first().email
        except KeyError:
            auth = response
            return auth
        
        auth = {"email": email, "username": username, "user_type" : user_type, "type": "kakao_access"}
        return auth
        
    
    
def refresh_token_auth(token: str = Depends(oauth2_bearer)):
    try:
        # if access token is expired, it will raise JWTError
        payload = jwt.decode(token, SECRET_KEY_REFRESH, algorithms=[ALGORITHM_ACCESS])
        token
        db = next(get_db())
        
        r_token_db = db.query(models.RefreshTokenDB).filter(models.RefreshTokenDB.email == payload.get('email')).first()
        
        if r_token_db.token != token:
            print("Refresh token is invalid")
            raise exceptions.refresh_token_expired_exception()
            
        print(f"email: {payload.get('email')}, user_id: {payload.get('user_id')}, connected")
        t_type: str = payload.get("type")
        
        email: str = payload.get("email")
        user_id: int = payload.get("user_id")
        
        if email is None or user_id is None:
            print("get_current_user: email or user_id is None")
            raise exceptions.get_user_exception()
        
        return {"email": email, "user_id": user_id, "type": t_type}
    except ExpiredSignatureError:
        print("Refresh token is expired. Please login again.")
        raise exceptions.refresh_token_expired_exception()
    except JWTError: # JWTError happens when token is expired or invalid
        print("Refresh token is invalid. Please login again.")
        
        raise exceptions.refresh_token_expired_exception()
    
def create_access_token(email: str, user_id: int, verified: bool = False,
                    expires_delta: Optional[timedelta] = ACCESS_TOKEN_EXPIRES):
    to_encode = {"email": email, "user_id": user_id, "verified": verified}
    expire = datetime.utcnow() + expires_delta # 2 hours
        
    # update subject expire time and if it's access token
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_ACCESS, algorithm=ALGORITHM_ACCESS)
    return encoded_jwt

def kakao_idtoken(id_token: str = Depends(oauth2_bearer)):
    decoded_token = jwt.decode(id_token, algorithms=[ALGORITHM_ACCESS], verify=False)
    verified = verify_kakao_idtoken(decoded_token)
    
def verify_kakao_idtoken(decoded_token):
    pass

def kakaologin_access(token: str = Depends(oauth2_bearer)):
    url = "https://kapi.kakao.com/v2/user/me"
    header = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=header).json()
    try:
        username = response['kakao_account']['profile']['nickname']
        email = response['kakao_account']['email']
    except KeyError:
        auth = response
        return auth
    
    auth = {"email_kakao": email, "username": username}
    
    return auth

def kakao_refresh(refresh_token: str = Depends(oauth2_bearer)):
    # 토큰 갱신하기
    url_refresh = "https://kauth.kakao.com/oauth/token"
    headers = {
        "Content-type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "refresh_token",
        "client_id": settings.KAKAO_RESTAPI_KEY,
        "refresh_token": refresh_token,
        "client_secret": settings.KAKAO_CLIENT_SECRET
    }

    # Send the request and handle errors
    try:
        response_refresh = requests.post(url_refresh, headers=headers, data=data)
        response_refresh.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print_message(f"Error: {e}")
        print_message(f"Response content: {e.response.content}")
        # Handle the error or raise it again

    # Print the response content
    print_message(f"Send refresh token response: {response_refresh.content}")
    
    return response_refresh.json()

def kakao_logout(access_token: str = Depends(oauth2_bearer)):
    url = "https://kapi.kakao.com/v1/user/logout"
    header = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(url, headers=header)
    print_message(response.status_code)
    print_message(response.json())
    
    json_data = response.json()
    json_data.update({"status_code": response.status_code})
    return json_data
    
def kakaologin_logout(token):
    url = "https://kapi.kakao.com/v1/user/logout"
    

# refresh token expires in 1 months
def create_refresh_token(email: str, user_id: int,
                    expires_delta: Optional[int] = REFRESH_TOKEN_EXPIRES):
    to_encode = {"email": email, "user_id": user_id}
    expire = datetime.utcnow() + expires_delta # 1 months
    
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_REFRESH, algorithm=ALGORITHM_ACCESS)
    
    return encoded_jwt

def authenticated_access_token_check(auth: dict, db: Session = None, verify: bool = False):
    '''
    description:
        - check if user is authenticated or not
        - raise exception if user is not authenticated
    args:
        - auth: dict = {email: str, user_id: int, type: str}
        - db: Session = database session
    return:
        - bool = True if user is authenticated, False if user is not authenticated
    '''
    
    if auth.get('type') == 'kakao_access':
        return True
    
    # 유저가 데이터베이스에 있는지 확인
    if db:
        if db.query(models.UsersDB).filter(models.UsersDB.email == auth['email']).first() is None:
            print("User is not in database")
            raise exceptions.get_user_exception()
    
    # 이메일 인증된 회원인지 확인
    if verify:
        if db is None:
            db = next(get_db()) # mysql 불러오기
            
        is_verified = db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == auth['email']).first()
        if is_verified is None or is_verified.verified is False:
            raise exceptions.not_verified_email_exception(auth['email'])
    
    if auth is None:
        print("User is not authenticated")
        raise exceptions.get_user_exception()
    if 'type' in auth.keys() and auth['type'] == 'refresh':
        return False
    
    return True

def get_password_hashed(password):
    return bcrypt_context.hash(password)

def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)