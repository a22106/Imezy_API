from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from modules.api import models

# auth
from passlib.context import CryptContext
from jose import JWTError, jwt


SECRET_KEY = "secret_api_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 120*12 # 24 hours
REFRESH_TOKEN_EXPIRES_MINUTES = 3*30*24*60 # 3 months


oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_current_user(token: str = Depends(oauth2_bearer)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        user_id: int = payload.get("user_id")
        print(f"email: {email}, user_id: {user_id}, connected")
        if email is None or user_id is None:
            print("get_current_user: email or user_id is None")
            raise get_user_exception()
        return {"email": email, "user_id": user_id}
    except JWTError: # JWTError happens when token is expired or invalid
        print("JWT error")
        raise get_jwt_exception()
    
def get_user_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. user exception",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception

def get_admin_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. not a admin user",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception

def get_jwt_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. jwt error exception",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception

def token_exception():
    token_exception_response = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. token exception",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return token_exception_response

def create_access_token(email: str, user_id: int, 
                    expires_delta: Optional[timedelta] = None):
    to_encode = {"email": email, "user_id": user_id}
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)
    
        
        
    # update subject expire time and if it's access token
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_ACCESS, algorithm=ALGORITHM_ACCESS)
    return encoded_jwt

# refresh token expires in 3 months
def create_refresh_token(email: str, user_id: int, 
                    expires_delta: Optional[timedelta] = None):
    to_encode = {"email": email, "user_id": user_id}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else: # else 1 day
        expire = datetime.utcnow() + timedelta(minutes=24*60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticated_access_token_check(auth: dict, db: Session = None):
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
    
    if db:
        if (user_db := db.query(models.UsersDB).filter(models.UsersDB.email == auth['email']).first()) is None:
            print("User is not in database")
            raise exceptions.get_user_exception()
    
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