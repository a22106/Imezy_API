# -*- coding: utf-8 -*-
from .database import engine, SessionLocal, get_db
from . import models, auths, credits
from .logs import print_message
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import exc, or_



def read_users(db):
    """Read all users from the database.

    Returns:
        A list of users.
    """
    return db.query(models.UsersDB).all()

def update_password(db: Session, user):
    """Update the password of a user in the database.

    Args:
        user: The user to update.
        password: The new password.

    Returns:
        The updated user.
    """
    user_updating = db.query(models.UsersDB).filter(models.UsersDB.email == user.email).first()

    if not auths.verify_password(user.old_password, user_updating.hashed_password):
        return False

    user_updating.hashed_password = auths.get_password_hashed(user.new_password)
    db.add(user_updating)
    db.commit()
    db.refresh(user_updating)
    return True

def update_user(db: Session, user_id, user):
    """Update the password of a user in the database.

    Args:
        user: The user to update. Contains name, email, is_active, and is_admin.
    Returns:
        The updated user.
    """
    user_updating = db.query(models.UsersDB).filter(models.UsersDB.id == user_id).first()

    for attr in user.__dict__.keys():
        if getattr(user, attr) != None:
            print(f"{attr}: {getattr(user, attr)}")
            setattr(user_updating, attr, getattr(user, attr))
        
    db.add(user_updating)
    db.commit()
    db.refresh(user_updating)
    
    response_user_info = user_updating.__dict__
    del response_user_info["hashed_password"], response_user_info["created_date"]
    response = {"code": 200, "message": "User updated", "data": response_user_info}
    return response

def delete_user(db: Session, user_id):
    """Delete a user from the database.

    Args:
        user_id: The id of the user to delete.

    Returns:
        The deleted user.
    """
    user = db.query(models.UsersDB).filter(models.UsersDB.id == user_id).first()
    db.delete(user)
    db.commit()
    return user

def create_user_kakao(new_user:dict):
    """_summary_

    Args:
        new_user (dict): {"email_kakao": email, "username": username}
    """
    
    db = next(get_db())
    if db.query(models.UsersKakaoDB).filter(models.UsersKakaoDB.email_kakao == new_user["email_kakao"]).first():
        print_message(f"User {new_user['email_kakao']} already exists")
        return False
    
    print(f"Creating user: {new_user['email_kakao']}, {new_user['username']}")
    new_kakao_db = models.UsersKakaoDB()
    new_kakao_db.username = new_user["username"]
    new_kakao_db.email_kakao = new_user["email_kakao"]
    db.add(new_kakao_db)
    
    try:
        db.commit()
        print_message(f'User {new_kakao_db.email_kakao} created successfully')
        return True
    except exc.IntegrityError as e:
        db.rollback()
        print_message(f"Error: {e}")
        print_message(f"Failed to create user {new_kakao_db.email_kakao}")
        raise HTTPException(status_code=400, 
                            detail=f"Failed to create user {new_kakao_db.email_kakao}")

def create_user(new_user):
    """Create a user in the database.

    Args:
        user: The user to create. Contains name, email, password, is_active, and is_admin.

    Returns:
        The created user.
    """
    
    db = next(get_db())
    if db.query(models.UsersDB).filter(models.UsersDB.email == new_user["email"]).first():
        print_message(f"User {new_user['email']} already exists")
        return False
    
    print_message(f"Creating user: {new_user['email']}, {new_user['username']}")
    is_exist = db.query(models.UsersDB).filter(
        or_(
            models.UsersDB.username == new_user["username"],
            models.UsersDB.email == new_user["email"].lower()
        )
    ).all()

    if is_exist:
        if is_exist[0].username == new_user["username"]:
            print_message(f'The username ({new_user["username"]}) is already in use')
            raise HTTPException(status_code=400, detail=f"username", headers={"username": new_user["username"]})
        else:
            print_message(f"The email {new_user['email']} is already in use")
            raise HTTPException(status_code=400, detail=f"email", headers={"email": new_user["email"]})
    
    new_user_db = models.UsersDB()
    new_user_db.email = new_user["email"].lower()
    new_user_db.username = new_user["username"]
    new_user_db.is_active = new_user["is_active"]
    if new_user["type"] == "normal":
        new_user_db.hashed_password = auths.get_password_hashed(new_user["password"])
    new_user_db.is_admin = new_user["is_admin"]
    if new_user["type"] == "kakao":
        new_user_db.email_kakao = new_user["email"].lower()
    print_message(f"Creating user: {new_user_db.email}, {new_user_db.username}")
    db.add(new_user_db)
    print_message(f"Created a new user to db: {new_user_db.email}, {new_user_db.username}")
    
    try:
        db.commit()
        print_message(f'User {new_user_db.email} created successfully')
        if new_user["is_admin"]:
            add_admin = models.UsersAdminDB()
            add_admin.email = new_user["email"].lower()
            db.add(add_admin)
            db.commit()
    except exc.IntegrityError as e:
        db.rollback()
        print_message(f"Error: {e}")
        print_message(f"Failed to create user {new_user_db.email}")
        raise HTTPException(status_code=400, 
                            detail=f"Failed to create user {new_user_db.email}, Error: {e}")
    
    # 신규 유저의 크래딧 정보를 생성
    create_credits = credits.create_new_credit_db(new_user_db.email)
    print(f"creating credits: {create_credits}")

    return {"message": f'User {new_user["username"]} created successfully'}

def read_user_info(auth: dict):
    db = next(get_db())
    # Get user info from database.
    try:
        user_db = db.query(models.UsersDB).filter(models.UsersDB.email == auth["email"]).first().__dict__
    except AttributeError:
        raise HTTPException(status_code=404, detail=f"User not found with email {auth['email']}")
    
    # Delete sensitive information that should not be returned.
    del user_db['hashed_password'], user_db['_sa_instance_state']
    
    # Get user credits from database.
    credits_db= db.query(models.CreditsDB).filter(models.CreditsDB.email == user_db["email"]).first()
    if credits_db is None:
        user_db['credits'] = 0
    else:
        user_db['credits'] = credits_db.credits
        
    # Get user verified status from database.
    if (verified_db := db.query(models.VerifyEmailDB).filter(models.VerifyEmailDB.email == user_db["email"]).first()) is None:
        user_db['verified'] = False
    else:
        user_db['verified'] = verified_db.verified
    print_message(f'Read user info: {user_db["email"]}')
    return user_db

def read_user_info_kakao(auth: dict) -> dict:
    db = next(get_db())
    
    try:
        user_db = db.query(models.UsersDB) \
            .filter(models.UsersDB.email == auth["email"]).first()
        credits_db = db.query(models.CreditsDB) \
            .filter(models.CreditsDB.email == auth["email"]).first()
    except AttributeError: # User not found
        raise HTTPException(status_code=404, detail=f"User not found with email {auth['email_kakao']}")
    except Exception as e: # 내부 서버 오류
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")
    
    user_info = {
            "detail": "kakao login success",
            "id": user_db.id,
            "username": auth["username"],
            "email": user_db.email,
            "created_date": user_db.created_date,
            "credits": credits_db.credits,
            "verified": True,
        }
        
    return user_info
        
def verify_user(email: dict) -> dict:
    print_message(f"Verifying user: {email}")
    db = next(get_db())
    try:
        if db.query(models.UsersDB).filter(models.UsersDB.email == email).first() is None: # 유저 DB 테이블에 없는 경우
            raise HTTPException(status_code=404, detail=f"User not found with email {email} on users table")
        
        if (verify_email_db := db.query(models.VerifyEmailDB) \
            .filter(models.VerifyEmailDB.email == email).first()) is None: # 이메일 인증 DB 테이블에 없는 경우
            verify_email_db = models.VerifyEmailDB()
            verify_email_db.email = email
            verify_email_db.verified = True
            db.add(verify_email_db)
            db.commit()
            print_message(f"User {email} verified successfully")
            return {"message": f"User {email} verified successfully"}
        else: # 이메일 인증 DB 테이블에 있는 경우
            verify_email_db.verified = True
            db.commit()
            print_message(f"User {email} verified successfully")
            return {"message": f"User {email} verified successfully"}
    except AttributeError: # auth에 email 값이 없는 경우
        raise HTTPException(status_code=404, detail=f"User not found with email {email}")
    except exc.IntegrityError:
        db.rollback()
        print_message(f"Failed to verify user {email}")
        raise HTTPException(status_code=400, detail=f"Failed to verify user {email}")
            