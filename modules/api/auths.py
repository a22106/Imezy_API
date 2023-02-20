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

def access_token_auth(token: str = Depends(oauth2_bearer)):
    decoded_token = jwt.decode(token, algorithms=[ALGORITHM_ACCESS], verify=False)
    
    if 'iss' in decoded_token and decoded_token['iss'] == 'https://kauth.kakao.com':
        """토큰 검증
        1. ID 토큰의 영역 구분자인 온점(.)을 기준으로 헤더, 페이로드, 서명을 분리
        2. 페이로드를 Base64 방식으로 디코딩
        3. 페이로드의 iss 값이 https://kauth.kakao.com와 일치하는지 확인
        4. 페이로드의 aud 값이 서비스 앱 키와 일치하는지 확인
        5. 페이로드의 exp 값이 현재 UNIX 타임스탬프(Timestamp)보다 큰 값인지 확인(ID 토큰이 만료되지 않았는지 확인)
        6. 페이로드의 nonce 값이 카카오 로그인 요청 시 전달한 값과 일치하는지 확인
        7. 서명 검증
        서명 검증은 다음 순서로 진행합니다.

        1. 헤더를 Base64 방식으로 디코딩
        2. OIDC: 공개키 목록 조회하기를 통해 카카오 인증 서버가 서명 시 사용하는 공개키 목록 조회
        3. 공개키 목록에서 헤더의 kid에 해당하는 공개키 값 확인
        - 공개키는 일정 기간 캐싱(Caching)하여 사용할 것을 권장하며, 지나치게 빈번한 요청 시 요청이 차단될 수 있으므로 유의
        4. JWT 서명 검증을 지원하는 라이브러리를 사용해 공개키로 서명 검증
        참고: OpenID Foundation, jwt.io
        라이브러리를 사용하지 않고 직접 서명 검증 구현 시, RFC7515 규격에 따라 서명 검증 과정 진행 가능"""
        #check decoded_token is equal to settings.KAKAO_RESTAPI_KEY
        if decoded_token['aud'] != settings.KAKAO_RESTAPI_KEY:
            print_message("aud is not equal to KAKAO_RESTAPI_KEY")
            raise exceptions.get_jwt_exception("aud is not equal to KAKAO_RESTAPI_KEY")
        if decoded_token['exp'] < datetime.now().timestamp():
            print_message("token is expired")
            raise exceptions.get_jwt_exception("token is expired")
        
        # if the token is valid, check the user is in the database
        email = decoded_token['kakao_account']['email']
        username = decoded_token['kakao_account']['profile']['nickname']
        db = next(get_db())
        if (kakao_user_db := db.query(models.UsersKakaoDB).filter(models.UsersKakaoDB.email_kakao == email_kakao).first()) is None:
            # users_kakao DB에 추가
            new_kakao_user = models.UserDB(email=email, email_kakao = email, username=username)
            db.add(new_kakao_user)
            db.commit()
            db.refresh(new_kakao_user) #
            # users DB에도 추가
            new_user ={
                "username": username,
                "email": email,
                "password": None,
                "is_active": True,
                "is_admin": False,
            }
            users.create_user(db, new_user)
            
            user_id = new_kakao_user.id
            email = new_kakao_user.email
            t_type = "kakao_access"
            
            return {"email": email, "user_id": user_id, "type": t_type}
        else:
            user_id = kakao_user_db.id
            email = kakao_user_db.email
            t_type = "kakao_access"
            return {"email": email, "user_id": user_id, "type": t_type}
    
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
    print(response)
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
        db = next(get_db())
        if db.query(models.UsersKakaoDB).filter(models.UsersKakaoDB.email == auth['email']).first() is None:
            print("User is not in database")
            raise exceptions.get_user_exception()
        else:
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
    if auth['type'] == 'refresh':
        return False
    return True

def get_password_hashed(password):
    return bcrypt_context.hash(password)

def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)