# -*- coding: utf-8 -*-
from fastapi import HTTPException, status
from .logs import print_message

def get_user_not_found_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="User not found"
    )
    print_message("get_user_not_found_exception", bad_request_exception)
    return bad_request_exception

def get_incorrent_password_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Incorrect password"
    )
    print_message("get_incorrent_password_exception", bad_request_exception)
    return bad_request_exception

def get_not_active_user_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Not active user"
    )
    print_message("get_not_active_user_exception", bad_request_exception)
    return bad_request_exception

def get_user_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. user exception",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("get_user_exception", credentials_exception)
    return credentials_exception

def get_update_credit_failed_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. update credit failed",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("get_update_credit_failed_exception", credentials_exception)
    return credentials_exception


def get_admin_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. not a admin user",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("get_admin_exception", credentials_exception)
    return credentials_exception

def get_jwt_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. The access token is expired or invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("get_jwt_exception", credentials_exception)
    return credentials_exception

def access_token_expired_exception():
    expired_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="The access token is expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("access_token_expired_exception", expired_exception)
    return expired_exception

def refresh_token_expired_exception():
    expired_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="The refresh token is expired or invalid, please login again",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("refresh_token_expired_exception", expired_exception)
    return expired_exception
    
def token_exception():
    token_exception_response = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. token exception",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("token_exception", token_exception_response)
    return token_exception_response

def refresh_token_exception():
    refresh_token_exception_response = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="The refresh token is expired or invalid, please login again",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("refresh_token_exception", refresh_token_exception_response)
    return refresh_token_exception_response


def not_enough_credits_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail="Could not validate credentials. not enough credits",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("not_enough_credits_exception", credentials_exception)
    return credentials_exception

# 부적절한 사용자 접근 예외
def get_inappropriate_user_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Inappropriate user access exception"
    )
    print_message("get_inappropriate_user_exception", bad_request_exception)
    return bad_request_exception

# File not exist exception
def get_file_not_exist_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="File not exist exception"
    )
    print_message("get_file_not_exist_exception", bad_request_exception)
    return bad_request_exception

def invalid_email_exception(error):
    inval_email_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"{error}",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message("InvalidEmailError", inval_email_exception)
    return inval_email_exception

def not_verified_email_exception(email: str):
    exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail= f"{email+' '}Email not verified",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message(f"{email+' '}Email not verified")
    return exception

def code_exception_exception(exception_code: int):
    """
    exception_code: 0 -> expired, 1 -> incorrect
    """
    exceptions = {0: "expired", 1: "incorrect"}
    exception_type = exceptions.get(exception_code) # expired or incorrect
    
    exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST if exception_type == "expired" 
                else status.HTTP_404_NOT_FOUND,
        detail= f"code exception{' '+exception_type}",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print_message(f"code exception{' '+exception_type}")
    return exception