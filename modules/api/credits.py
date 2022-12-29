from .database import engine, SessionLocal
from . import models
from .auth import verify_password, get_password_hashed
# from .models import CreditsHistoryDB, CreditsDB
from .models import CreditsDB, UpdateCreditsRequest
from datetime import datetime

from sqlalchemy.orm import Session

def read_creds(db: Session, owner_email: int = None):
    """Read all credentials from the database.

    Returns:
        A list of credentials.
    """
    if owner_email:
        return db.query(models.CreditsDB).filter(models.CreditsDB.owner_email == owner_email).all()
    return db.query(models.CreditsDB).all()

def update_cred_by_id(owner_email: str, cred: UpdateCreditsRequest, db: Session):
    current_cred_db = db.query(models.CreditsDB).filter(models.CreditsDB.owner_email == owner_email).first()
    current_cred_db.credits = current_cred_db.credits + cred.credits_inc
    current_cred_db.last_updated = datetime.utcnow()
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
    
    current_cred_db = db.query(models.CreditsDB).filter(models.CreditsDB.owner_email == owner_email).first()
    current_cred_db.credits = current_cred_db.credits + cred_inc
    current_cred_db.last_updated = datetime.utcnow()
    db.add(current_cred_db)
    
    update_cred_db = models.CreditsUpdateDB()
    update_cred_db.owner_email = owner_email
    update_cred_db.credits_inc = cred_inc
    update_cred_db.updated = current_cred_db.last_updated
    db.add(update_cred_db)
    
    
    try:
        db.commit()
        db.refresh(current_cred_db)
    except Exception as e:
        db.rollback()
        print("Error: ", e)
        return False
    
    return current_cred_db.credits