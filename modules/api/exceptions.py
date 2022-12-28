from fastapi import HTTPException, status

def get_user_not_found_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="User not found"
    )
    return bad_request_exception

def get_incorrent_password_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Incorrect password"
    )
    return bad_request_exception

def get_not_active_user_exception():
    bad_request_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Not active user"
    )
    return bad_request_exception

def get_user_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. user exception",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception

def get_update_credit_failed_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. update credit failed",
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
        detail="Could not validate credentials. the token is expired or invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception

def get_jwt_expired_exception():
    expired_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. the token is expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return expired_exception

def token_exception():
    token_exception_response = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. token exception",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return token_exception_response


def not_enough_credits_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. not enough credits",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception