from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession  # Note: Using sync for simplicity; switch to async if needed
from app.models import User
from app.auth import hash_password, generate_totp_secret
from app.config import settings

def create_user(session: AsyncSession, email: str, password: str, phrase: str = None) -> User:
    if phrase is None:
        phrase = settings.ANTI_PHISHING_PHRASE_DEFAULT
    user = User(email=email, password_hash=hash_password(password), phrase=phrase)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def get_user_by_email(session: AsyncSession, email: str) -> User:
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def update_user(session: AsyncSession, user: User, updates: dict) -> User:
    for key, value in updates.items():
        setattr(user, key, value)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def enable_totp(session: AsyncSession, user: User) -> str:
    secret = generate_totp_secret()
    user.totp_secret = secret
    session.add(user)
    session.commit()
    return secret

