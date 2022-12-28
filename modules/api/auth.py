from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from modules.api import models
from dataclasses import dataclass

from pydantic import ValidationError

# auth
from passlib.context import CryptContext
from jose import JWTError, jwt, ExpiredSignatureError

from . import exceptions


SECRET_KEY_ACCESS = "secret_api_key"
# SECRET_KEY_REFRESH = "secret_refresh"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = timedelta(minutes=1)
REFRESH_TOKEN_EXPIRES_MINUTES = timedelta(days=30)


oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_current_user(token: str = Depends(oauth2_bearer)):
    
    try:
        # if access token is expired, it will raise JWTError
        payload = jwt.decode(token, SECRET_KEY_ACCESS, algorithms=[ALGORITHM]
                             , )
        print(f"email: {payload.get('email')}, user_id: {payload.get('user_id')}, connected")
        t_type: str = payload.get("type")
        
        email: str = payload.get("email")
        user_id: int = payload.get("user_id")
        
        if email is None or user_id is None:
            print("get_current_user: email or user_id is None")
            raise exceptions.get_user_exception()
        
        return {"email": email, "user_id": user_id, "type": t_type}
    except ExpiredSignatureError:
        print("JWT is expired")
        raise exceptions.get_jwt_expired_exception()
    except JWTError: # JWTError happens when token is expired or invalid
        print("JWT is invalid")
        raise exceptions.get_jwt_exception()
    
def create_access_token(email: str, user_id: int, 
                    expires_delta: Optional[timedelta] = timedelta(seconds=120)):
    to_encode = {"email": email, "user_id": user_id}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)
    # update subject expire time and if it's access token
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_ACCESS, algorithm=ALGORITHM)
    return encoded_jwt

# refresh token expires in 3 months
def create_refresh_token(email: str, user_id: int, 
                    expires_delta: Optional[timedelta] = timedelta(days=30)):
    to_encode = {"email": email, "user_id": user_id}
    
    expire = datetime.utcnow() + expires_delta
    
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_ACCESS, algorithm=ALGORITHM)
    
    return encoded_jwt

def get_password_hashed(password):
    return bcrypt_context.hash(password)

def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)