
from .database import engine, SessionLocal
from . import models
from .auth import verify_password, get_password_hash

from sqlalchemy.orm import Session

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

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

    if not verify_password(user.old_password, user_updating.hash_password):
        return False

    user_updating.hash_password = get_password_hash(user.new_password)
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

    if user.username.lower() == "String" or user.email.lower() == "String":
        return False
    print(f"Updating user {user.username} with email {user.email} and is_active {user.is_active} and is_admin {user.is_admin}")
    user_updating.username = user.username
    user_updating.email = user.email.lower()
    user_updating.is_active = user.is_active
    user_updating.is_admin = user.is_admin
    db.add(user_updating)
    db.commit()
    db.refresh(user_updating)
    return user

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