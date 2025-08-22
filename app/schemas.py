from pydantic import BaseModel, EmailStr
from typing import Optional

# Register
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    phrase: Optional[str] = None

# Login
class UserLogin(BaseModel):
    email: EmailStr
    password: str
    totp: Optional[str] = None

# Token
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# Refresh
class TokenRefresh(BaseModel):
    refresh_token: str

# Password Reset Request
class PasswordResetRequest(BaseModel):
    email: EmailStr

# User Profile
class UserProfile(BaseModel):
    email: EmailStr
    role: str
    phrase: str

# Update User
class UserUpdate(BaseModel):
    phrase: Optional[str] = None

# TOTP Enable
class TOTPEnableResponse(BaseModel):
    secret: str
    qr_code: str  # Base64 encoded QR image
