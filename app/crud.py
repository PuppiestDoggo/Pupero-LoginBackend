from sqlalchemy.ext.asyncio.session import AsyncSession
from sqlmodel import select
from sqlmodel import Session
from app.models import User
from app.auth import hash_password, generate_totp_secret
from app.config import settings

def create_user(session: Session, email: str, password: str, phrase: str = None, username: str = None) -> User:
    if phrase is None:
        phrase = settings.ANTI_PHISHING_PHRASE_DEFAULT
    user = User(email=email, username=username, password_hash=hash_password(password), phrase=phrase)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def get_user_by_email(session: Session, email: str) -> User:
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def get_user_by_username(session: AsyncSession, username: str) -> User:
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()

def update_user(session: AsyncSession, user: User, updates: dict) -> User:
    for key, value in updates.items():
        setattr(user, key, value)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def delete_user(session: AsyncSession, user: User) -> None:
    session.delete(user)
    session.commit()

def crud_enable_totp(session: AsyncSession, user: User) -> str:
    secret = generate_totp_secret()
    user.totp_secret = secret
    session.add(user)
    session.commit()
    return secret

def set_totp_secret(session: AsyncSession, user: User, secret: str) -> User:
    user.totp_secret = secret
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def disable_totp(session: AsyncSession, user: User) -> User:
    user.totp_secret = None
    session.add(user)
    session.commit()
    session.refresh(user)
    return user




def crud_disable_totp(session: AsyncSession, user: User) -> User:
    """Backward-compatible wrapper to disable TOTP for a user.
    Sets user's totp_secret to None, persists changes, and returns the updated user.
    """
    return disable_totp(session, user)
