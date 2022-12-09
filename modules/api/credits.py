from .database import engine, SessionLocal
from . import models
from .auth import verify_password, get_password_hash
# from .models import CreditsHistoryDB, CreditsDB
from .models import CreditsDB

from sqlalchemy.orm import Session

def read_all_creds(db: Session):
    """Read all credentials from the database.

    Returns:
        A list of credentials.
    """
    return db.query(models.CreditsDB).all()

def read_cred_by_id(user_id: int, db: Session):
    """Read a credential from the database by its id.

    Args:
        user_id: The id of the credential to read.

    Returns:
        The credential.
    """
    return db.query(models.CreditsDB).filter(models.CreditsDB.id == user_id).first()

def update_cred_by_id(user_id: int, cred, db: Session):
    current_cred = db.query(models.CreditsDB).filter(models.CreditsDB.user_id == user_id).first()
    cred_update = CreditsDB()
    cred_update.user_email = cred.user_email
    cred_update.credits = current_cred.credits + cred.credits_inc
    cred_update.user_id = user_id
    db.add(cred_update)
    
    try:
        db.commit()
        db.refresh(cred_update)
    except:
        db.rollback()
        raise
    
    return True