from fastapi import FastAPI, Depends, HTTPException, status, Form, Body, Request
from typing import Optional
from sqlmodel import Session, select
import logging
import json
import time
from datetime import timedelta
from app.database import get_session
from app.crud import create_user, get_user_by_email, update_user, crud_enable_totp, set_totp_secret, crud_disable_totp, delete_user
from app.auth import verify_password, create_access_token, create_refresh_token, verify_token, verify_totp, \
    generate_totp_qr, generate_totp_secret
from app.deps import get_current_user
from app.models import User
from app.schemas import UserRegister, UserLogin, Token, TokenRefresh, PasswordResetRequest, UserProfile, UserUpdate, TOTPEnableResponse, TOTPEnableConfirm, DeleteAccountRequest
from app.config import settings
from datetime import datetime

app = FastAPI(title="Pupero Auth Service")

# Basic health endpoint for docker healthcheck
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# Alias for k8s/monitoring expectations
@app.get("/health")
def health():
    return {"status": "ok"}

# Basic JSON logging setup
logger = logging.getLogger("pupero_auth")
if not logger.handlers:
    handler = logging.StreamHandler()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    process_time = time.time() - start
    # Try to extract user from Authorization header
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    user_email = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1]
        user_email = verify_token(token)
    log_record = {
        "event": "http_request",
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
        "latency_ms": int(process_time * 1000),
        "user": user_email,
        "client": request.client.host if request.client else None,
    }
    logger.info(json.dumps(log_record))
    return response

# Note: Database schema creation has been moved to the separate CreateDB utility.

@app.post("/register", response_model=dict)
def register(user_in: UserRegister, session: Session = Depends(get_session)):
    existing_user = get_user_by_email(session, user_in.email)
    if existing_user:
        logger.info(json.dumps({"event": "register_conflict", "email": user_in.email}))
        raise HTTPException(status_code=400, detail="Email already registered")
    # Ensure username present; if missing, derive from email local-part
    username = (user_in.username or user_in.email.split("@")[0]).strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    # Enforce uniqueness
    from app.crud import get_user_by_username
    if get_user_by_username(session, username):
        logger.info(json.dumps({"event": "register_conflict_username", "username": username}))
        raise HTTPException(status_code=400, detail="Username already taken")
    user = create_user(session, user_in.email, user_in.password, username=username)
    logger.info(json.dumps({"event": "register_success", "user": user.email}))

    # Attempt to create a Matrix account for the user using their username and website password (best-effort)
    try:
        if getattr(settings, "MATRIX_ENABLED", True) and getattr(settings, "MATRIX_HS_URL", None):
            import httpx
            base = settings.MATRIX_HS_URL.rstrip("/")
            # sanitize localpart
            raw = (user.username or "").strip().lower()
            allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._=-")
            localpart = ''.join(ch if ch in allowed else '_' for ch in raw).strip('_') or f"{getattr(settings,'MATRIX_USER_PREFIX','u')}{user.id}"
            url = base + "/_matrix/client/v3/register"
            payload = {"username": localpart, "password": user_in.password, "auth": {"type": "m.login.dummy"}}
            with httpx.Client(timeout=10.0) as client:
                r = client.post(url, json=payload)
                if r.status_code in (200, 201):
                    # persist matrix_localpart
                    update_user(session, user, {"matrix_localpart": localpart})
                    logger.info(json.dumps({"event": "matrix_register", "user_id": user.id, "localpart": localpart, "status": r.status_code}))
                else:
                    try:
                        data = r.json()
                        if r.status_code == 400 and data.get("errcode") == "M_USER_IN_USE":
                            update_user(session, user, {"matrix_localpart": localpart})
                            logger.info(json.dumps({"event": "matrix_register_exists", "user_id": user.id, "localpart": localpart}))
                        else:
                            logger.warning(json.dumps({"event": "matrix_register_failed", "user_id": user.id, "status": r.status_code, "body": data}))
                    except Exception:
                        logger.warning(json.dumps({"event": "matrix_register_failed", "user_id": user.id, "status": r.status_code, "body": r.text}))
        else:
            logger.info(json.dumps({"event": "matrix_register_skip", "reason": "MATRIX not enabled or HS URL not set", "user_id": user.id}))
    except Exception as e:
        logger.warning(json.dumps({"event": "matrix_register_error", "user_id": user.id, "error": str(e)}))

    # Attempt to create a Monero subaddress for the user (non-fatal on error)
    try:
        if settings.MONERO_SERVICE_URL:
            import httpx
            label = user.username or f"user_{user.id}"
            def _normalize_monero_base(val: str | None) -> str:
                if not val:
                    return "http://monero:8004"
                v = val.strip().rstrip("/")
                if "://" in v:
                    return v
                if v in {"api-manager", "pupero-api-manager"}:
                    return f"http://{v}:8000/monero"
                if v in {"monero", "pupero-WalletManager"}:
                    return f"http://{v}:8004"
                return "http://monero:8004"
            base = _normalize_monero_base(settings.MONERO_SERVICE_URL)
            url = base + "/addresses"
            payload = {"user_id": user.id, "label": label}
            with httpx.Client(timeout=10.0) as client:
                r = client.post(url, json=payload)
                ok = r.status_code in (200, 201)
                logger.info(json.dumps({"event": "monero_address_create", "user_id": user.id, "status": r.status_code, "ok": ok}))
        else:
            logger.info(json.dumps({"event": "monero_address_skip", "reason": "MONERO_SERVICE_URL not set", "user_id": user.id}))
    except Exception as e:
        logger.warning(json.dumps({"event": "monero_address_error", "user_id": user.id, "error": str(e)}))

    return {"user_id": user.id}

@app.post("/login", response_model=Token)
def login(credentials: UserLogin, session: Session = Depends(get_session)):
    user = None
    if credentials.username:
        from app.crud import get_user_by_username
        user = get_user_by_username(session, credentials.username)
    elif credentials.email:
        user = get_user_by_email(session, credentials.email)
    if not user or not verify_password(credentials.password, user.password_hash):
        logger.info(json.dumps({"event": "login_failed", "username": credentials.username, "email": credentials.email}))
        raise HTTPException(status_code=400, detail="Incorrect username/email or password")
    if user.totp_secret:
        if not credentials.totp or not verify_totp(user.totp_secret, credentials.totp):
            logger.info(json.dumps({"event": "login_failed_2fa", "user": user.email}))
            raise HTTPException(status_code=400, detail="Invalid or missing 2FA code")
    access_exp = None
    refresh_exp = None
    if credentials.remember_me:
        access_exp = timedelta(days=settings.REMEMBER_ME_DAYS)
        refresh_exp = timedelta(days=settings.REMEMBER_ME_DAYS)
    access_token = create_access_token(user.email, expires_delta=access_exp)
    refresh_token = create_refresh_token(user.email, expires_delta=refresh_exp)

    # Best-effort: also login to Matrix to obtain a matrix_access_token
    matrix_token = None
    try:
        if getattr(settings, "MATRIX_ENABLED", True) and getattr(settings, "MATRIX_HS_URL", None):
            import httpx
            base = settings.MATRIX_HS_URL.rstrip("/")
            local = user.matrix_localpart
            if not local:
                raw = (user.username or "").strip().lower()
                allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._=-")
                local = ''.join(ch if ch in allowed else '_' for ch in raw).strip('_') or f"{getattr(settings,'MATRIX_USER_PREFIX','u')}{user.id}"
            payload = {"type": "m.login.password", "user": local, "password": credentials.password}
            with httpx.Client(timeout=10.0) as client:
                r = client.post(base + "/_matrix/client/v3/login", json=payload)
                if r.status_code == 200:
                    matrix_token = (r.json() or {}).get("access_token")
    except Exception:
        matrix_token = None

    logger.info(json.dumps({"event": "login_success", "user": user.email, "remember_me": bool(credentials.remember_me)}))
    return {"access_token": access_token, "refresh_token": refresh_token, "matrix_access_token": matrix_token}

@app.post("/refresh", response_model=Token)
def refresh(token_in: TokenRefresh, session: Session = Depends(get_session)):
    email = verify_token(token_in.refresh_token)
    if not email:
        logger.info(json.dumps({"event": "refresh_failed"}))
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = get_user_by_email(session, email)
    if not user:
        logger.info(json.dumps({"event": "refresh_user_not_found", "email": email}))
        raise HTTPException(status_code=401, detail="User not found")
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)  # Optionally rotate refresh token
    logger.info(json.dumps({"event": "refresh_success", "user": user.email}))
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
    return UserProfile(id=current_user.id, email=current_user.email, username=current_user.username, role=current_user.role, phrase=current_user.phrase)

@app.put("/user/update", response_model=dict)
def update_profile(update_in: UserUpdate, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    updates = {}
    # Update phrase
    if update_in.phrase is not None:
        updates["phrase"] = update_in.phrase
    # Update username
    if update_in.username:
        from app.crud import get_user_by_username
        if update_in.username != current_user.username:
            if get_user_by_username(session, update_in.username):
                raise HTTPException(status_code=400, detail="Username already taken")
            updates["username"] = update_in.username
    # Update email (requires current_password)
    tokens = {}
    if update_in.new_email:
        if not update_in.current_password or not verify_password(update_in.current_password, current_user.password_hash):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        from app.crud import get_user_by_email
        if update_in.new_email != current_user.email and get_user_by_email(session, update_in.new_email):
            raise HTTPException(status_code=400, detail="Email already registered")
        updates["email"] = update_in.new_email
        # Issue new tokens because subject (email) changed
        tokens = {
            "access_token": create_access_token(update_in.new_email),
            "refresh_token": create_refresh_token(update_in.new_email)
        }
    # Update password (requires current_password)
    if update_in.new_password:
        if not update_in.current_password or not verify_password(update_in.current_password, current_user.password_hash):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        from app.auth import hash_password
        updates["password_hash"] = hash_password(update_in.new_password)
        # Optionally rotate tokens on password change (keep same subject)
        if not tokens:
            tokens = {
                "access_token": create_access_token(current_user.email),
                "refresh_token": create_refresh_token(current_user.email)
            }
    if updates:
        # If password changed, attempt to update Matrix password too (best-effort)
        if "password_hash" in updates:
            try:
                if getattr(settings, "MATRIX_ENABLED", True) and getattr(settings, "MATRIX_HS_URL", None):
                    import httpx
                    base = settings.MATRIX_HS_URL.rstrip("/")
                    local = current_user.matrix_localpart or (current_user.username or "").strip().lower()
                    if not local:
                        local = f"{getattr(settings,'MATRIX_USER_PREFIX','u')}{current_user.id}"
                    # UIA password change
                    payload = {
                        "auth": {
                            "type": "m.login.password",
                            "identifier": {"type": "m.id.user", "user": local},
                            "password": update_in.current_password
                        },
                        "new_password": update_in.new_password
                    }
                    with httpx.Client(timeout=10.0) as client:
                        client.post(base + "/_matrix/client/v3/account/password", json=payload)
            except Exception:
                pass
        update_user(session, current_user, updates)
        logger.info(json.dumps({"event": "profile_update", "user": current_user.email, "fields": list(updates.keys())}))
    resp = {"message": "Profile updated"}
    if tokens:
        resp.update(tokens)
    return resp


@app.post("/totp/enable/start", response_model=TOTPEnableResponse)
def start_totp_enable(current_user: User = Depends(get_current_user)):
    if current_user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP already enabled")
    # Generate a secret and QR but DO NOT persist yet
    secret = generate_totp_secret()
    qr_code = generate_totp_qr(current_user.email, secret)
    logger.info(json.dumps({"event": "totp_enable_start", "user": current_user.email}))
    return {"secret": secret, "qr_code": qr_code}

@app.post("/totp/enable/confirm", response_model=dict)
def confirm_totp_enable(
    payload: TOTPEnableConfirm,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    if current_user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP already enabled")
    if not verify_totp(payload.secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid 2FA code")
    set_totp_secret(session, current_user, payload.secret)
    logger.info(json.dumps({"event": "totp_enabled", "user": current_user.email}))
    return {"message": "TOTP enabled"}

@app.post("/totp/disable", response_model=dict)
def disable_totp(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP not enabled")
    crud_disable_totp(session, current_user)
    logger.info(json.dumps({"event": "totp_disabled", "user": current_user.email}))
    return {"message": "TOTP disabled"}


@app.get("/totp/status", response_model=dict)
def totp_status(current_user: User = Depends(get_current_user)):
    return {"enabled": bool(current_user.totp_secret)}

# GDPR-compliant Delete Account endpoint
@app.delete("/user/delete", response_model=dict)
def delete_account(
    payload: DeleteAccountRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    # Require explicit confirmation
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Confirmation checkbox is required")
    # Verify current password
    if not payload.current_password or not verify_password(payload.current_password, current_user.password_hash):
        logger.info(json.dumps({"event": "delete_failed_bad_password", "user": current_user.email}))
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    # If TOTP enabled, verify if provided
    if current_user.totp_secret:
        if not payload.totp or not verify_totp(current_user.totp_secret, payload.totp):
            logger.info(json.dumps({"event": "delete_failed_2fa", "user": current_user.email}))
            raise HTTPException(status_code=400, detail="Invalid or missing 2FA code")
    email = current_user.email
    delete_user(session, current_user)
    logger.info(json.dumps({"event": "account_deleted", "user": email}))
    return {"message": "Account deleted"}


# --- Admin endpoints ---
from fastapi import APIRouter
admin_router = APIRouter(prefix="/admin", tags=["Admin"])

def _require_admin(user: User):
    role = (user.role or "").strip().lower()
    if role not in {"admin", "superadmin"}:
        raise HTTPException(status_code=403, detail="Admin privileges required")

@admin_router.get("/users")
def admin_list_users(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    rows = session.exec(select(User)).all()
    out = []
    for u in rows:
        out.append({
            "id": u.id,
            "email": u.email,
            "username": u.username,
            "role": u.role,
            "is_disabled": bool(u.is_disabled),
            "created_at": u.created_at,
            "force_logout_at": u.force_logout_at,
            "matrix_localpart": u.matrix_localpart,
        })
    return {"users": out}

@admin_router.post("/users/{user_id}/disable")
def admin_disable_user(user_id: int, payload: dict = Body(default={}), current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    disabled = bool(payload.get("disabled", True))
    update_user(session, target, {"is_disabled": disabled})
    return {"user_id": user_id, "is_disabled": disabled}

@admin_router.post("/users/{user_id}/role")
def admin_set_role(user_id: int, payload: dict = Body(default={}), current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    new_role = (payload.get("role") or "").strip().lower()
    if new_role not in {"user", "admin", "superadmin"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    update_user(session, target, {"role": new_role})
    return {"user_id": user_id, "role": new_role}

@admin_router.post("/users/{user_id}/password")
def admin_reset_password(user_id: int, payload: dict = Body(default={}), current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    new_password = payload.get("new_password")
    if not new_password or len(str(new_password)) < 6:
        raise HTTPException(status_code=400, detail="Password too short")
    from app.auth import hash_password
    update_user(session, target, {"password_hash": hash_password(new_password)})
    # Note: As requested, do NOT update Matrix here (admin does not have current password for UIA)
    return {"user_id": user_id, "message": "password_reset"}

@admin_router.post("/users/{user_id}/logout")
def admin_force_logout(user_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    update_user(session, target, {"force_logout_at": datetime.utcnow()})
    return {"user_id": user_id, "message": "logout_forced"}

app.include_router(admin_router)
