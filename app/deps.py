from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session
from jose import jwt, JWTError
from app.auth import verify_token, ALGORITHM
from app.crud import get_user_by_email
from app.database import get_session
from app.config import settings
from datetime import datetime

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    email = verify_token(token)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = get_user_by_email(session, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    # Enforce disabled flag
    if getattr(user, 'is_disabled', False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    # Enforce force_logout_at using token iat
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[ALGORITHM])
        iat = payload.get("iat")
        if iat and getattr(user, 'force_logout_at', None):
            try:
                # iat may be datetime or timestamp
                iat_dt = datetime.utcfromtimestamp(iat) if isinstance(iat, (int, float)) else datetime.fromisoformat(str(iat))
                if iat_dt < user.force_logout_at:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired; please log in again")
            except ValueError:
                pass
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user
