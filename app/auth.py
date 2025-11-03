from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from pyotp import TOTP, random_base32
from app.config import settings
from app.schemas import Token
import qrcode
import io
import base64

# Password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT
ALGORITHM = "HS256"

def create_access_token(subject: str, expires_delta: timedelta = None) -> str:
    now = datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"iat": now, "exp": expire, "sub": subject}
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(subject: str, expires_delta: timedelta = None) -> str:
    now = datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode = {"iat": now, "exp": expire, "sub": subject}
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

# TOTP
def generate_totp_secret() -> str:
    return random_base32()

def verify_totp(secret: str, totp_code: str) -> bool:
    totp = TOTP(secret)
    return totp.verify(totp_code)

def generate_totp_qr(email: str, secret: str) -> str:
    totp = TOTP(secret)
    uri = totp.provisioning_uri(email, issuer_name="Pupero")
    img = qrcode.make(uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")
