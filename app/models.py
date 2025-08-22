from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(max_length=255, index=True, unique=True)
    username: Optional[str] = Field(default=None, max_length=50, index=True, unique=True)
    password_hash: str = Field(max_length=255)
    role: str = Field(default="user", max_length=50)
    totp_secret: Optional[str] = Field(default=None, max_length=32)
    phrase: str = Field(max_length=255)  # Anti-phishing phrase
    created_at: datetime = Field(default_factory=datetime.utcnow)