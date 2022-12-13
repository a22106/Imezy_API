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

def update_cred_by_id(owner_email: int, cred: UpdateCreditsRequest, db: Session):
    current_cred = db.query(models.CreditsDB).filter(models.CreditsDB.owner_email == owner_email).first()
    current_cred.credits = current_cred.credits + cred.credits_inc
    current_cred.last_updated = datetime.utcnow()
    db.add(current_cred)
    
    try:
        db.commit()
        db.refresh(current_cred)
    except:
        db.rollback()
        raise
    
    return True