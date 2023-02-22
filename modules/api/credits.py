# -*- coding: utf-8 -*-
from .database import get_db
from . import models
from .auths import verify_password, get_password_hashed
# from .models import CreditsHistoryDB, CreditsDB
from .models import CreditsDB, UpdateCreditsRequest
from datetime import datetime
from .logs import print_message
from sqlalchemy import exc
from fastapi import HTTPException

from sqlalchemy.orm import Session

def read_creds(db: Session, owner_email: int = None):
    """Read all credentials from the database.

    Returns:
        A list of credentials.
    """
    if owner_email:
        return db.query(models.CreditsDB).filter(models.CreditsDB.email == owner_email).all()
    return db.query(models.CreditsDB).all()

def update_cred_by_id(owner_email: str, cred: UpdateCreditsRequest, db: Session):
    current_cred_db = db.query(models.CreditsDB).filter(models.CreditsDB.email == owner_email).first()
    current_cred_db.credits = current_cred_db.credits + cred.credits_inc
    current_cred_db.last_updated = datetime.now()
    db.add(current_cred_db)
    
    try:
        db.commit()
        db.refresh(current_cred_db)
    except:
        db.rollback()
        raise
    
    return True

def update_cred(owner_email: str, cred_inc: int, db: Session):
    ''' Update the credits of a user in the database.
    args:
        owner_email: The user to update.
        cred_inc: The new credits.
    '''
    
    current_cred_db = db.query(models.CreditsDB).filter(models.CreditsDB.email == owner_email).first()
    current_cred_db.credits = current_cred_db.credits + cred_inc
    current_cred_db.last_updated = datetime.now()
    db.add(current_cred_db)
    
    update_cred_db = models.CreditsUpdateDB()
    update_cred_db.email = owner_email
    update_cred_db.credits_inc = cred_inc
    update_cred_db.updated = current_cred_db.last_updated
    db.add(update_cred_db)
    
    
    try:
        db.commit()
        db.refresh(current_cred_db)
    except Exception as e:
        db.rollback()
        print("Error: ", e)
        return -1
    
    return current_cred_db.credits

def create_new_credit_db(owner_email: str):
    ''' Create a new credit database for a user.
    args:
        owner_email: The user to create a new credit database.
    '''
    db = next(get_db())
    
    # 신규 유저 생성시, 기본적으로 1000 credits를 부여한다.
    new_credit = models.CreditsDB()
    new_credit.email = owner_email
    db.add(new_credit)
    
    try:
        db.commit()
        print_message(f'Credits for user {owner_email} created successfully')
    except exc.IntegrityError as e:
        db.rollback()
        db.query(models.UsersDB) \
            .filter(models.UsersDB.email == owner_email).delete()
        db.commit()
        print_message(f"Failed to create credits for the user {owner_email}")
        raise HTTPException(status_code=400, detail=f"Failed to create credits for the user {owner_email}, Error: {e}")
    except Exception as e:
        db.rollback()
        db.query(models.UsersDB) \
            .filter(models.UsersDB.email == owner_email).delete()
        db.commit()
        print_message(f"Failed to create credits for the user {owner_email}, Error: {e}")
        raise HTTPException(status_code=400, 
                            detail=f"Failed to create credits for the user {owner_email}, Error: {e}")
    
    return new_credit