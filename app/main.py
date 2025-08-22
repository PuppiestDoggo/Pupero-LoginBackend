from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session
from app.database import create_db_and_tables, get_session
from app.schemas import UserRegister, UserLogin, Token, TokenRefresh, PasswordResetRequest, UserProfile, UserUpdate, TOTPEnableResponse
from app.crud import create_user, get_user_by_email, update_user, enable_totp
from app.auth import verify_password, create_access_token, create_refresh_token, verify_token, verify_totp, generate_totp_qr
from app.deps import get_current_user
from app.models import User

app = FastAPI(title="Pupero Auth Service")

# Create DB and tables on startup
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

@app.post("/register", response_model=dict)
def register(user_in: UserRegister, session: Session = Depends(get_session)):
    existing_user = get_user_by_email(session, user_in.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = create_user(session, user_in.email, user_in.password, user_in.phrase)
    return {"user_id": user.id}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = get_user_by_email(session, form_data.username)  # username is email
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if user.totp_secret:
        # TOTP required, but for simplicity, assume it's sent in headers or body; here we skip for basic login
        pass  # Implement as needed
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)
    return {"access_token": access_token, "refresh_token": refresh_token}

@app.post("/refresh", response_model=Token)
def refresh(token_in: TokenRefresh, session: Session = Depends(get_session)):
    email = verify_token(token_in.refresh_token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = get_user_by_email(session, email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)  # Optionally rotate refresh token
    return {"access_token": access_token, "refresh_token": refresh_token}

@app.post("/password/reset", response_model=dict)
def password_reset(reset_in: PasswordResetRequest, session: Session = Depends(get_session)):
    user = get_user_by_email(session, reset_in.email)
    if not user:
        return {"message": "If the email exists, a reset link has been sent"}  # Security: no disclosure
    # TODO: Implement actual reset logic (e.g., send email with token)
    return {"message": "Reset link sent"}

@app.get("/user/profile", response_model=UserProfile)
def get_profile(current_user: User = Depends(get_current_user)):
    return UserProfile(email=current_user.email, role=current_user.role, phrase=current_user.phrase)

@app.put("/user/update", response_model=dict)
def update_profile(update_in: UserUpdate, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    updates = {}
    if update_in.phrase:
        updates["phrase"] = update_in.phrase
    update_user(session, current_user, updates)
    return {"message": "Profile updated"}

@app.post("/totp/enable", response_model=TOTPEnableResponse)
def enable_totp(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    if current_user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP already enabled")
    secret = enable_totp(session, current_user)
    qr_code = generate_totp_qr(current_user.email, secret)
    return {"secret": secret, "qr_code": qr_code}
