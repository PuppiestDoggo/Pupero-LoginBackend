from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field
from sqlalchemy.sql import func

class User(SQLModel, table=True):
    __tablename__ = "user"
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    username: Optional[str] = Field(default=None, index=True)
    password_hash: str
    role: str = Field(default="user")
    is_disabled: bool = Field(default=False, index=True)
    force_logout_at: Optional[datetime] = Field(default=None, index=True)
    totp_secret: Optional[str] = None
    matrix_localpart: Optional[str] = Field(default=None, index=True)
    phrase: str
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.current_timestamp()})