from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    username: Optional[str] = None

class UserLogin(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    password: str
    totp: Optional[str] = None
    remember_me: Optional[bool] = False

class Token(BaseModel):
    access_token: str
    refresh_token: str
    matrix_access_token: Optional[str] = None

class TokenRefresh(BaseModel):
    refresh_token: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class UserProfile(BaseModel):
    id: int
    email: EmailStr
    username: Optional[str] = None
    role: str
    phrase: str

class UserUpdate(BaseModel):
    username: Optional[str] = None
    new_email: Optional[EmailStr] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None
    phrase: Optional[str] = None

class TOTPEnableResponse(BaseModel):
    secret: str
    qr_code: str  # base64 PNG

class TOTPEnableConfirm(BaseModel):
    secret: str
    code: str

class DeleteAccountRequest(BaseModel):
    current_password: str
    totp: Optional[str] = None
    confirm: bool = False
