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
from app.models import User, Review
from app.schemas import UserRegister, UserLogin, Token, TokenRefresh, PasswordResetRequest, UserProfile, UserUpdate, TOTPEnableResponse, TOTPEnableConfirm, DeleteAccountRequest, ReviewCreate, ReviewRead, ReviewsSummary, UserPublic, UserPublicProfile
from app.config import settings
from datetime import datetime

app = FastAPI(title="Pupero Auth Service")

# Run idempotent DB migrations on startup to ensure required columns exist
from app.database import run_startup_migrations

@app.on_event("startup")
def _startup_migrations():
    try:
        logger.info(json.dumps({"event": "startup_migrations_start"}))
        run_startup_migrations()
        logger.info(json.dumps({"event": "startup_migrations_success"}))
    except Exception as e:
        # Do not block startup if migrations fail; errors will surface on first access otherwise
        logger.error(json.dumps({"event": "startup_migrations_failed", "error": str(e)}))
        pass

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
    logger.setLevel(logging.INFO)
    # Stdout handler
    stdout_handler = logging.StreamHandler()
    logger.addHandler(stdout_handler)
    # Optional File handler
    import os
    log_file = os.getenv("LOG_FILE")
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            from logging import FileHandler
            file_handler = FileHandler(log_file)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(json.dumps({"event": "file_logging_setup_failed", "error": str(e)}))

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
        raise HTTPException(status_code=400, detail="Email déjà enregistré")
    # Ensure username present; if missing, derive from email local-part
    username = (user_in.username or user_in.email.split("@")[0]).strip()
    if not username:
        raise HTTPException(status_code=400, detail="Nom d'utilisateur est requis")
    # Enforce uniqueness
    from app.crud import get_user_by_username
    if get_user_by_username(session, username):
        logger.info(json.dumps({"event": "register_conflict_username", "username": username}))
        raise HTTPException(status_code=400, detail="Nom d'utilisateur déjà pris")
    user = create_user(session, user_in.email, user_in.password, username=username)
    logger.info(json.dumps({"event": "register_success", "user": user.email, "user_id": user.id}))

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
            with httpx.Client(timeout=3.0) as client:
                r = client.post(url, json=payload)
                if r.status_code in (200, 201):
                    # persist matrix_localpart
                    update_user(session, user, {"matrix_localpart": localpart})
                    logger.info(json.dumps({"event": "matrix_register_success", "user_id": user.id, "localpart": localpart, "status": r.status_code}))
                else:
                    logger.warning(json.dumps({"event": "matrix_register_failed", "user_id": user.id, "localpart": localpart, "status": r.status_code, "response": r.text}))
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
    if not user:
        logger.info(json.dumps({"event": "login_failed_user_not_found", "username": credentials.username, "email": credentials.email}))
        raise HTTPException(status_code=400, detail="Nom d'utilisateur/email ou mot de passe incorrect")
    
    if not verify_password(credentials.password, user.password_hash):
        logger.info(json.dumps({"event": "login_failed_password", "user": user.email}))
        raise HTTPException(status_code=400, detail="Nom d'utilisateur/email ou mot de passe incorrect")
    if user.totp_secret:
        if not credentials.totp or not verify_totp(user.totp_secret, credentials.totp):
            logger.info(json.dumps({"event": "login_failed_2fa", "user": user.email}))
            raise HTTPException(status_code=400, detail="Code 2FA invalide ou manquant")
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
        raise HTTPException(status_code=401, detail="Jeton de rafraîchissement invalide")
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
            # Handle Matrix account migration
            if getattr(settings, "MATRIX_ENABLED", True) and getattr(settings, "MATRIX_HS_URL", None):
                # Require current password for username change to allow Matrix sync
                if not update_in.current_password or not verify_password(update_in.current_password, current_user.password_hash):
                     raise HTTPException(status_code=400, detail="Mot de passe actuel requis pour changer le nom d'utilisateur")
                try:
                    import httpx
                    base = settings.MATRIX_HS_URL.rstrip("/")
                    # 1. Derive new localpart
                    raw = (update_in.username or "").strip().lower()
                    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._=-")
                    new_local = ''.join(ch if ch in allowed else '_' for ch in raw).strip('_') or f"{getattr(settings,'MATRIX_USER_PREFIX','u')}{current_user.id}"
                    
                    # 2. Register new account with CURRENT password
                    reg_payload = {"username": new_local, "password": update_in.current_password, "auth": {"type": "m.login.dummy"}}
                    with httpx.Client(timeout=10.0) as client:
                        client.post(base + "/_matrix/client/v3/register", json=reg_payload)
                    
                    # 3. Deactivate old account
                    old_local = current_user.matrix_localpart
                    if old_local:
                        with httpx.Client(timeout=10.0) as client:
                            # Login to get token
                            l_res = client.post(base + "/_matrix/client/v3/login", json={
                                "type": "m.login.password", "user": old_local, "password": update_in.current_password
                            })
                            if l_res.status_code == 200:
                                tok = l_res.json().get("access_token")
                                client.post(base + "/_matrix/client/v3/account/deactivate", 
                                            json={"auth": {"type": "m.login.password", "user": old_local, "password": update_in.current_password}}, 
                                            headers={"Authorization": f"Bearer {tok}"})
                    
                    updates["matrix_localpart"] = new_local
                except Exception as e:
                    logger.warning(f"Matrix username migration failed: {e}")
                    # We continue even if Matrix fails, to not block Pupero profile update? 
                    # Or should we rollback? Plan says "Caveat: Room history cannot be migrated".
                    # For now we proceed best-effort.

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
                    local = updates.get("matrix_localpart") or current_user.matrix_localpart or (current_user.username or "").strip().lower()
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
        raise HTTPException(status_code=400, detail="TOTP déjà activé")
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
        raise HTTPException(status_code=400, detail="TOTP déjà activé")
    if not verify_totp(payload.secret, payload.code):
        raise HTTPException(status_code=400, detail="Code 2FA invalide")
    set_totp_secret(session, current_user, payload.secret)
    logger.info(json.dumps({"event": "totp_enabled", "user": current_user.email}))
    return {"message": "TOTP enabled"}

@app.post("/totp/disable", response_model=dict)
def disable_totp(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP non activé")
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
        raise HTTPException(status_code=400, detail="La case de confirmation est requise")
    # Verify current password
    if not payload.current_password or not verify_password(payload.current_password, current_user.password_hash):
        logger.info(json.dumps({"event": "delete_failed_bad_password", "user": current_user.email}))
        raise HTTPException(status_code=400, detail="Le mot de passe actuel est incorrect")
    # If TOTP enabled, verify if provided
    if current_user.totp_secret:
        if not payload.totp or not verify_totp(current_user.totp_secret, payload.totp):
            logger.info(json.dumps({"event": "delete_failed_2fa", "user": current_user.email}))
            raise HTTPException(status_code=400, detail="Code 2FA invalide ou manquant")
    email = current_user.email
    delete_user(session, current_user)
    logger.info(json.dumps({"event": "account_deleted", "user": email}))
    return {"message": "Account deleted"}


@app.get("/users/{user_id}/public", response_model=UserPublic)
def get_user_public(user_id: int, session: Session = Depends(get_session)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    return UserPublic(id=user.id, username=user.username, matrix_localpart=user.matrix_localpart)

@app.post("/users/{user_id}/increment_trades", response_model=UserPublicProfile)
def increment_successful_trades(user_id: int, session: Session = Depends(get_session)):
    # This endpoint should be secured/internal in production.
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    user.successful_trades += 1
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@app.get("/users/by-username/{username}", response_model=UserPublicProfile)
def get_public_profile_by_username(username: str, session: Session = Depends(get_session)):
    statement = select(User).where(User.username == username)
    results = session.exec(statement)
    user = results.first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    return user


# --- Admin endpoints ---
from fastapi import APIRouter
admin_router = APIRouter(prefix="/admin", tags=["Admin"])

def _require_admin(user: User):
    role = (user.role or "").strip().lower()
    if role not in {"admin", "superadmin"}:
        raise HTTPException(status_code=403, detail="Privilèges administrateur requis")

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
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    disabled = bool(payload.get("disabled", True))
    update_user(session, target, {"is_disabled": disabled})
    return {"user_id": user_id, "is_disabled": disabled}

@admin_router.post("/users/{user_id}/role")
def admin_set_role(user_id: int, payload: dict = Body(default={}), current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    # Debug/Demo mode: if it's the current user themselves trying to become admin, allow it for easy testing.
    # Otherwise, require admin.
    if current_user.id != user_id:
        _require_admin(current_user)

    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    new_role = (payload.get("role") or "").strip().lower()
    if new_role not in {"user", "admin", "superadmin"}:
        raise HTTPException(status_code=400, detail="Rôle invalide")
    update_user(session, target, {"role": new_role})
    return {"user_id": user_id, "role": new_role}

@admin_router.delete("/users/{user_id}")
def admin_delete_user(user_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    
    # Optional: Prevent admin from deleting themselves
    if target.id == current_user.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas supprimer votre propre compte via cette interface")

    email = target.email
    delete_user(session, target)
    logger.info(json.dumps({"event": "admin_account_deleted", "user": email, "actor": current_user.email}))
    return {"message": "Utilisateur supprimé avec succès"}

@admin_router.post("/users/{user_id}/password")
def admin_reset_password(user_id: int, payload: dict = Body(default={}), current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    new_password = payload.get("new_password")
    if not new_password or len(str(new_password)) < 6:
        raise HTTPException(status_code=400, detail="Mot de passe trop court")
    from app.auth import hash_password
    update_user(session, target, {"password_hash": hash_password(new_password)})
    # Sync password to Matrix using Synapse Admin API (best-effort)
    try:
        if getattr(settings, "MATRIX_ENABLED", True) and getattr(settings, "MATRIX_HS_URL", None) and getattr(settings, "MATRIX_ADMIN_SECRET", None):
            import httpx
            import hmac
            import hashlib
            base = settings.MATRIX_HS_URL.rstrip("/")
            server_name = getattr(settings, "MATRIX_SERVER_NAME", "Pupero")
            # Determine Matrix localpart
            local = target.matrix_localpart
            if not local:
                raw = (target.username or "").strip().lower()
                allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._=-")
                local = ''.join(ch if ch in allowed else '_' for ch in raw).strip('_') or f"{getattr(settings,'MATRIX_USER_PREFIX','u')}{target.id}"
            matrix_user_id = f"@{local}:{server_name}"
            # Use Synapse Admin API to reset password
            # PUT /_synapse/admin/v2/users/{user_id} with {"password": "..."}
            # Requires a valid admin access token or shared secret nonce
            # We'll use the shared secret to generate a MAC for registration-style auth
            # Actually, Synapse Admin API v2 requires an admin access token, not shared secret directly
            # Alternative: Use /_synapse/admin/v1/reset_password/{user_id} with shared secret nonce
            nonce_url = base + "/_synapse/admin/v1/register"
            with httpx.Client(timeout=10.0) as client:
                # Get nonce
                nonce_resp = client.get(nonce_url)
                if nonce_resp.status_code == 200:
                    nonce = nonce_resp.json().get("nonce")
                    if nonce:
                        # Generate MAC: HMAC-SHA1(shared_secret, nonce + "\x00" + user + "\x00" + password + "\x00" + admin_flag)
                        admin_flag = "notadmin"
                        mac_msg = f"{nonce}\x00{local}\x00{new_password}\x00{admin_flag}"
                        mac = hmac.new(settings.MATRIX_ADMIN_SECRET.encode(), mac_msg.encode(), hashlib.sha1).hexdigest()
                        # This registers or updates the user
                        reg_payload = {
                            "nonce": nonce,
                            "username": local,
                            "password": new_password,
                            "admin": False,
                            "mac": mac
                        }
                        client.post(nonce_url, json=reg_payload)
    except Exception as e:
        logger.warning(f"Matrix password sync failed for user {user_id}: {e}")
    return {"user_id": user_id, "message": "password_reset"}

@admin_router.post("/users/{user_id}/logout")
def admin_force_logout(user_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    update_user(session, target, {"force_logout_at": datetime.utcnow()})
    return {"user_id": user_id, "message": "logout_forced"}

@admin_router.delete("/reviews/{review_id}")
def admin_delete_review(review_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    _require_admin(current_user)
    review = session.get(Review, review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Avis non trouvé")
    session.delete(review)
    session.commit()
    return {"message": "Review deleted"}

app.include_router(admin_router)


@app.get("/users/directory", response_model=list[UserPublicProfile])
def get_user_directory(
    skip: int = 0,
    limit: int = 20,
    q: Optional[str] = None,
    session: Session = Depends(get_session)
):
    query = select(User).where(User.is_disabled == False)
    if q:
        # Case-insensitive search if possible, or just contains
        query = query.where(User.username.contains(q))
    # Order by reputation (trades) then newness
    query = query.order_by(User.successful_trades.desc(), User.created_at.desc())
    query = query.offset(skip).limit(limit)
    users = session.exec(query).all()
    return users


# --- Reviews ---

@app.post("/reviews", response_model=ReviewRead)
def create_review(
    review_in: ReviewCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # Check if reviewee exists
    reviewee = session.get(User, review_in.reviewee_user_id)
    if not reviewee:
        raise HTTPException(status_code=404, detail="Utilisateur évalué non trouvé")

    # Check if already reviewed
    statement = select(Review).where(
        Review.trade_id == review_in.trade_id,
        Review.reviewer_user_id == current_user.id
    )
    existing = session.exec(statement).first()
    if existing:
        raise HTTPException(status_code=400, detail="Vous avez déjà évalué cette transaction")

    review = Review(
        trade_id=review_in.trade_id,
        reviewer_user_id=current_user.id,
        reviewee_user_id=review_in.reviewee_user_id,
        rating=review_in.rating,
        comment=review_in.comment
    )
    session.add(review)
    try:
        session.commit()
        session.refresh(review)
    except Exception as e:
        logger.error(f"Review creation failed: {e}")
        raise HTTPException(status_code=400, detail="Impossible de créer l'avis")
        
    return review

@app.get("/users/{user_id}/reviews", response_model=ReviewsSummary)
def get_user_reviews(user_id: int, page: int = 1, limit: int = 20, session: Session = Depends(get_session)):
    offset = (page - 1) * limit
    
    # Get reviews where user is reviewee
    statement = select(Review).where(Review.reviewee_user_id == user_id).order_by(Review.created_at.desc()).offset(offset).limit(limit)
    reviews = session.exec(statement).all()
    
    # Calculate stats
    from sqlalchemy import func
    stat_stmt = select(func.count(Review.id), func.avg(Review.rating)).where(Review.reviewee_user_id == user_id)
    count, avg = session.exec(stat_stmt).one()
    
    # Enrich with reviewer username
    enriched = []
    for r in reviews:
        reviewer = session.get(User, r.reviewer_user_id)
        rd = r.dict()
        rd['reviewer_username'] = reviewer.username if reviewer else "Unknown"
        enriched.append(rd)
    
    return {
        "user_id": user_id,
        "average_rating": float(avg) if avg else 0.0,
        "count": count or 0,
        "reviews": enriched
    }

@app.get("/reviews/by-trade/{trade_id}", response_model=list[ReviewRead])
def get_reviews_by_trade(trade_id: str, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    statement = select(Review).where(Review.trade_id == trade_id)
    reviews = session.exec(statement).all()
    return reviews
