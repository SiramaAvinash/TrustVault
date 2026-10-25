import hashlib, json, os, re, uuid, secrets, hmac
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Response, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, Response
from sqlalchemy import select, or_, func
from sqlalchemy.orm import Session
from app.core.config import settings, storage_path
from app.db.session import get_db
from app.models.entities import User, Document, Grant, AuditEvent, DocumentVersion, ApprovalRequest, LoginOTP, DeviceSession, AccessRequest
from app.schemas.api import LoginRequest, RegisterRequest, OTPVerifyRequest, UserOut, GoogleLoginRequest
from app.security.passwords import verify_password, hash_password
from app.security.tokens import create_access_token, decode_access_payload
from app.security.google_auth import verify_google_credential
from app.security.dependencies import get_current_user, require_admin
from app.services.audit import record_event, verify_chain
from app.services.authorization import get_document_or_404, permission_for, require_document_permission, active_grant
from app.services.notifications import notify, send_email
from app.services.watermark import watermark_pdf, watermark_image

router = APIRouter(prefix="/api")
logout_bearer = HTTPBearer(auto_error=False)
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg"}
ALLOWED_TYPES = {
    ".txt": {"text/plain"},
    ".pdf": {"application/pdf"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
}
MAX_BYTES = settings.max_upload_mb * 1024 * 1024

def _safe_filename(name: str) -> str:
    return Path(name or "document").name[:255]

def _validate_content(ext: str, content: bytes, content_type: str):
    if not content:
        raise HTTPException(status_code=400, detail="Empty files are not allowed")
    if ext == ".pdf" and not content.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="PDF signature does not match file content")
    if ext == ".png" and not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise HTTPException(status_code=400, detail="PNG signature does not match file content")
    if ext in (".jpg", ".jpeg") and not content.startswith(b"\xff\xd8\xff"):
        raise HTTPException(status_code=400, detail="JPEG signature does not match file content")
    if ext == ".txt" and b"\x00" in content:
        raise HTTPException(status_code=400, detail="Text file contains binary data")
    # Browser-provided MIME types are not trusted; signatures/extension checks are the primary controls.

def _doc_dict(db, doc, user):
    owner = db.get(User, doc.owner_id)
    return {
        "id": doc.id, "title": doc.title, "category": doc.category,
        "original_filename": doc.original_filename, "content_type": doc.content_type,
        "size_bytes": doc.size_bytes, "sha256": doc.sha256, "owner_id": doc.owner_id,
        "owner_name": owner.full_name if owner else "Unknown", "created_at": doc.created_at,
        "updated_at": doc.updated_at, "permission": permission_for(db, doc, user),
        "requires_approval": doc.requires_approval, "approval_status": doc.approval_status,
    }

def _device_label(user_agent: str) -> str:
    ua = (user_agent or "Unknown browser")[:500]
    browser = "Browser"
    for needle, label in (("Edg/", "Edge"), ("Chrome/", "Chrome"), ("Firefox/", "Firefox"), ("Safari/", "Safari")):
        if needle in ua:
            browser = label
            break
    os_name = "Unknown OS"
    for needle, label in (("Windows", "Windows"), ("Mac OS", "macOS"), ("Android", "Android"), ("iPhone", "iOS"), ("Linux", "Linux")):
        if needle in ua:
            os_name = label
            break
    return f"{browser} on {os_name}"[:160]

def _issue_session(db: Session, user: User, request: Request):
    session_id = str(uuid.uuid4())
    user_agent = request.headers.get("user-agent", "")[:500]
    ip_address = request.client.host if request.client else ""
    session = DeviceSession(id=session_id, user_id=user.id, device_label=_device_label(user_agent),
                            user_agent=user_agent, ip_address=ip_address)
    db.add(session)
    active = db.scalars(select(DeviceSession).where(DeviceSession.user_id == user.id,
        DeviceSession.revoked_at.is_(None))).all()
    # Record simultaneous sessions; this is a risk signal, not proof of an attacker.
    if active:
        record_event(db, user.id, "concurrent_session_alert", "session", session_id, "success",
                     {"active_sessions_before_login": len(active), "device": session.device_label,
                      "ip_address": ip_address, "note": "Multiple sessions may be legitimate; verify with the user."})
        admins = db.scalars(select(User).where(User.role == "admin", User.is_active.is_(True))).all()
        for admin in admins:
            if admin.email != user.email:
                send_email(admin.email, "TrustVault security alert: concurrent sign-in",
                           f"Account {user.email} signed in with another active session. Device: {session.device_label}; IP: {ip_address}. This is a risk signal, not proof of compromise.")
    else:
        record_event(db, user.id, "session_created", "session", session_id, "success",
                     {"device": session.device_label, "ip_address": ip_address})
    db.commit()
    return {"access_token": create_access_token(user.id, session_id), "token_type": "bearer",
            "user": UserOut.model_validate(user).model_dump(), "session_id": session_id}

@router.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = str(payload.email).strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=email, full_name=payload.full_name.strip(), password_hash=hash_password(payload.password), role="viewer", is_active=True)
    db.add(user); db.flush()
    record_event(db, user.id, "register", "user", user.id, "success", {"email": email, "role": "viewer"})
    db.commit(); db.refresh(user)
    return user

@router.post("/auth/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        record_event(db, user.id if user else None, "login", "user", user.id if user else None, "denied", {"email": email})
        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    user_agent = request.headers.get("user-agent", "")[:500]
    ip_address = request.client.host if request.client else ""
    known_device = db.scalar(select(DeviceSession.id).where(
        DeviceSession.user_id == user.id, DeviceSession.user_agent == user_agent,
        DeviceSession.ip_address == ip_address, DeviceSession.revoked_at.is_(None)
    ).limit(1))
    new_device_challenge = bool(settings.resend_api_key and settings.resend_from_email and not known_device)
    if settings.login_otp_every_time or user.two_factor_enabled or new_device_challenge:
        code = f"{secrets.randbelow(1_000_000):06d}"
        db.add(LoginOTP(user_id=user.id, code_hash=hashlib.sha256(code.encode()).hexdigest(), expires_at=datetime.now(timezone.utc)+timedelta(minutes=5)))
        sent = send_email(user.email, "TrustVault sign-in verification code", f"Your TrustVault verification code is {code}. It expires in 5 minutes. If you did not request it, secure your account.")
        record_event(db, user.id, "login_2fa_challenge", "user", user.id, "success" if sent else "error",
                     {"email": email, "reason": "enabled_2fa" if user.two_factor_enabled else "unrecognized_device"})
        db.commit()
        if not sent:
            raise HTTPException(status_code=503, detail="Sign-in verification email could not be sent. Check SMTP settings or ask the administrator.")
        return {"requires_2fa": True, "email": email, "message": "Verification code sent by email"}
    record_event(db, user.id, "login", "user", user.id, "success", {})
    db.commit()
    return _issue_session(db, user, request)

@router.post("/auth/google")
def google_login(payload: GoogleLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate a Google Identity Services ID token and issue a normal TrustVault session."""
    claims = verify_google_credential(payload.credential, settings.google_client_id)
    email = str(claims["email"]).strip().lower()
    google_sub = str(claims["sub"])
    full_name = str(claims.get("name") or email.split("@", 1)[0]).strip()[:120] or email

    user_by_sub = db.scalar(select(User).where(User.google_sub == google_sub))
    user_by_email = db.scalar(select(User).where(User.email == email))
    if user_by_sub and user_by_email and user_by_sub.id != user_by_email.id:
        record_event(db, None, "google_login", "user", None, "denied",
                     {"reason": "identity_email_conflict", "email": email})
        db.commit()
        raise HTTPException(status_code=409, detail="This Google identity conflicts with an existing TrustVault account")
    user = user_by_sub or user_by_email
    if user and not user.is_active:
        record_event(db, user.id, "google_login", "user", user.id, "denied", {"reason": "inactive_account"})
        db.commit()
        raise HTTPException(status_code=403, detail="This TrustVault account is inactive")
    if user and user.google_sub and user.google_sub != google_sub:
        record_event(db, user.id, "google_login", "user", user.id, "denied", {"reason": "google_identity_mismatch"})
        db.commit()
        raise HTTPException(status_code=409, detail="This email is already linked to a different Google identity")
    if not user:
        # Google-only accounts receive an unpredictable password hash and the least-privilege Viewer role.
        user = User(
            email=email,
            full_name=full_name,
            password_hash=hash_password(secrets.token_urlsafe(48)),
            google_sub=google_sub,
            role="viewer",
            is_active=True,
        )
        db.add(user)
        db.flush()
        record_event(db, user.id, "google_account_created", "user", user.id, "success",
                     {"email": email, "role": "viewer", "provider": "google"})
    elif not user.google_sub:
        # Only link by email after Google's signature and email_verified claim were validated above.
        user.google_sub = google_sub
        if not user.full_name and full_name:
            user.full_name = full_name

    if user.two_factor_enabled:
        code = f"{secrets.randbelow(1_000_000):06d}"
        db.add(LoginOTP(user_id=user.id, code_hash=hashlib.sha256(code.encode()).hexdigest(),
                        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)))
        sent = send_email(user.email, "TrustVault sign-in verification code",
                          f"Your TrustVault verification code is {code}. It expires in 5 minutes.")
        record_event(db, user.id, "google_login_2fa_challenge", "user", user.id,
                     "success" if sent else "error", {"provider": "google"})
        db.commit()
        if not sent:
            raise HTTPException(status_code=503, detail="Additional verification email could not be sent")
        return {"requires_2fa": True, "email": email, "message": "Additional verification code sent"}

    record_event(db, user.id, "google_login", "user", user.id, "success", {"provider": "google"})
    db.commit()
    return _issue_session(db, user, request)


@router.post("/auth/2fa/verify")
def verify_2fa(payload: OTPVerifyRequest, request: Request, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    user = db.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid verification request")
    now = datetime.now(timezone.utc)
    challenges = db.scalars(select(LoginOTP).where(LoginOTP.user_id == user.id, LoginOTP.used_at.is_(None)).order_by(LoginOTP.id.desc())).all()
    valid = None
    for challenge in challenges:
        expiry = challenge.expires_at if challenge.expires_at.tzinfo else challenge.expires_at.replace(tzinfo=timezone.utc)
        if expiry > now and challenge.attempts < 5 and hmac.compare_digest(challenge.code_hash, hashlib.sha256(payload.code.encode()).hexdigest()):
            valid = challenge; break
        challenge.attempts += 1
    if not valid:
        record_event(db, user.id, "login_2fa", "user", user.id, "denied", {"reason": "invalid_or_expired_code"}); db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")
    valid.used_at = now
    for challenge in challenges:
        if challenge.id != valid.id and challenge.used_at is None: challenge.used_at = now
    record_event(db, user.id, "login_2fa", "user", user.id, "success", {}); db.commit()
    return _issue_session(db, user, request)

@router.patch("/auth/2fa")
def set_2fa(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    enabled = payload.get("enabled")
    password = str(payload.get("password", ""))
    if not isinstance(enabled, bool) or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Provide enabled=true/false and your current password")
    if enabled and not (settings.resend_api_key and settings.resend_from_email):
        raise HTTPException(status_code=503, detail="Configure the Resend email provider before enabling email-based two-factor authentication")
    user.two_factor_enabled = enabled
    record_event(db, user.id, "two_factor_setting", "user", user.id, "success", {"enabled": enabled})
    db.commit()
    return {"two_factor_enabled": user.two_factor_enabled}

@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user

@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.scalars(select(User).order_by(User.full_name)).all()

@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: dict, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    target = db.get(User, user_id)
    if not target: raise HTTPException(status_code=404, detail="User not found")
    allowed = {"role", "is_active", "full_name"}
    if set(payload) - allowed: raise HTTPException(status_code=400, detail="Only role, is_active, and full_name can be changed")
    if "role" in payload:
        if payload["role"] not in ("admin", "owner", "viewer"): raise HTTPException(status_code=400, detail="Invalid role")
        if target.id == admin.id and payload["role"] != "admin": raise HTTPException(status_code=400, detail="You cannot remove your own administrator role")
        target.role = payload["role"]
    if "is_active" in payload:
        if not isinstance(payload["is_active"], bool): raise HTTPException(status_code=400, detail="is_active must be boolean")
        if target.id == admin.id and not payload["is_active"]: raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
        was_active = target.is_active
        target.is_active = payload["is_active"]
        if was_active and not target.is_active:
            now = datetime.now(timezone.utc)
            active_grants = db.scalars(select(Grant).where(Grant.user_id == target.id, Grant.revoked_at.is_(None))).all()
            for grant in active_grants:
                grant.revoked_at = now
                record_event(db, admin.id, "revoke_access_account_deactivated", "document", grant.document_id, "success", {"recipient_id": target.id})
    if "full_name" in payload: target.full_name = str(payload["full_name"]).strip()[:120] or target.full_name
    record_event(db, admin.id, "user_update", "user", target.id, "success", {"fields": sorted(payload.keys())})
    db.commit(); db.refresh(target)
    if not target.is_active:
        # Preserve grants for audit/history; authorization checks active accounts before each request.
        pass
    return UserOut.model_validate(target)

@router.get("/analytics")
def analytics(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == "admin":
        docs = db.scalars(select(Document)).all()
        events_query = select(AuditEvent)
    else:
        granted_ids = select(Grant.document_id).where(Grant.user_id == user.id, Grant.revoked_at.is_(None), or_(Grant.expires_at.is_(None), Grant.expires_at > datetime.now(timezone.utc)))
        docs = db.scalars(select(Document).where(or_(Document.owner_id == user.id, Document.id.in_(granted_ids)))).all()
        events_query = select(AuditEvent).where(AuditEvent.actor_id == user.id)
    events = db.scalars(events_query.order_by(AuditEvent.id.desc()).limit(1000)).all()
    now = datetime.now(timezone.utc)
    last_week = [d for d in docs if (d.created_at.replace(tzinfo=timezone.utc) if d.created_at.tzinfo is None else d.created_at) >= now - timedelta(days=7)]
    return {"document_count": len(docs), "owned_count": sum(d.owner_id == user.id for d in docs),
            "shared_count": sum(d.owner_id != user.id for d in docs), "uploads_last_7_days": len(last_week),
            "denied_events": sum(e.outcome == "denied" for e in events),
            "download_events": sum(e.action == "download" and e.outcome == "success" for e in events),
            "pending_approvals": db.scalar(select(func.count(ApprovalRequest.id)).where(ApprovalRequest.status == "pending")) if user.role == "admin" else 0}

@router.post("/documents")
async def upload_document(
    title: str = Form(...), category: str = Form("General"), requires_approval: bool = Form(False), file: UploadFile = File(...),
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    if user.role not in ("owner", "admin"):
        record_event(db, user.id, "upload", "document", None, "denied", {"reason": "role_not_allowed"}); db.commit()
        raise HTTPException(status_code=403, detail="Only document owners or administrators can upload documents")
    original = _safe_filename(file.filename or "document")
    ext = Path(original).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        record_event(db, user.id, "upload", "document", None, "denied", {"filename": original, "reason": "extension"})
        db.commit()
        raise HTTPException(status_code=400, detail="Allowed file types: TXT, PDF, PNG, JPG, JPEG")
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        record_event(db, user.id, "upload", "document", None, "denied", {"filename": original, "reason": "size"})
        db.commit()
        raise HTTPException(status_code=413, detail=f"Maximum upload size is {settings.max_upload_mb} MB")
    _validate_content(ext, content, file.content_type or "")
    storage_name = uuid.uuid4().hex
    path = storage_path / storage_name
    path.write_bytes(content)
    doc = Document(title=title.strip()[:255] or original, category=category.strip()[:100] or "General",
                   original_filename=original, storage_filename=storage_name,
                   content_type=(ALLOWED_TYPES[ext] and next(iter(ALLOWED_TYPES[ext]))),
                   size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest(), owner_id=user.id,
                   requires_approval=requires_approval, approval_status="pending" if requires_approval else "not_required")
    db.add(doc)
    db.flush()
    record_event(db, user.id, "upload", "document", doc.id, "success",
                 {"filename": original, "size_bytes": len(content), "sha256": doc.sha256, "requires_approval": requires_approval})
    if requires_approval:
        db.add(ApprovalRequest(document_id=doc.id, requested_by=user.id, status="pending", note="Approval requested during upload"))
        record_event(db, user.id, "approval_requested", "document", doc.id, "success", {})
    db.commit()
    db.refresh(doc)
    return _doc_dict(db, doc, user)

@router.get("/documents")
def list_documents(
    search: str | None = None, category: str | None = None, owner: str | None = None,
    date_from: str | None = None, date_to: str | None = None, file_type: str | None = None,
    permission: str | None = None, hash_prefix: str | None = None, sort_by: str = "created_at", sort_order: str = "desc",
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    stmt = select(Document).join(User, Document.owner_id == User.id)
    # Admin privileges manage users/audit; they do not implicitly expose private document contents.
    granted_ids = select(Grant.document_id).where(Grant.user_id == user.id, Grant.revoked_at.is_(None), or_(Grant.expires_at.is_(None), Grant.expires_at > datetime.now(timezone.utc)))
    stmt = stmt.where(or_(Document.owner_id == user.id, Document.id.in_(granted_ids)))
    if search:
        stmt = stmt.where(Document.title.ilike(f"%{search[:100]}%"))
    if category:
        stmt = stmt.where(Document.category.ilike(f"%{category[:100]}%"))
    if owner:
        stmt = stmt.where(User.full_name.ilike(f"%{owner[:100]}%"))
    if date_from:
        try:
            parsed_from = datetime.fromisoformat(date_from)
            if parsed_from.tzinfo is None: parsed_from = parsed_from.replace(tzinfo=timezone.utc)
            stmt = stmt.where(Document.created_at >= parsed_from)
        except ValueError:
            raise HTTPException(status_code=400, detail="date_from must be an ISO date or datetime")
    if date_to:
        try:
            parsed_to = datetime.fromisoformat(date_to)
            if parsed_to.tzinfo is None: parsed_to = parsed_to.replace(tzinfo=timezone.utc)
            if len(date_to) == 10: parsed_to = parsed_to.replace(hour=23, minute=59, second=59, microsecond=999999)
            stmt = stmt.where(Document.created_at <= parsed_to)
        except ValueError:
            raise HTTPException(status_code=400, detail="date_to must be an ISO date or datetime")
    if hash_prefix:
        stmt = stmt.where(Document.sha256.ilike(f"{hash_prefix[:64]}%"))
    if file_type:
        ext = file_type.lower().lstrip(".")[:10]
        stmt = stmt.where(Document.original_filename.ilike(f"%.{ext}"))
    sort_column = {"created_at": Document.created_at, "updated_at": Document.updated_at, "title": Document.title, "category": Document.category, "size": Document.size_bytes}.get(sort_by, Document.created_at)
    stmt = stmt.order_by(sort_column.asc() if sort_order.lower() == "asc" else sort_column.desc())
    docs = db.scalars(stmt).all()
    results = [_doc_dict(db, d, user) for d in docs]
    if permission:
        results = [item for item in results if item["permission"] == permission]
    return results

@router.get("/documents/{document_id}")
def get_document(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    require_document_permission(db, doc, user, "read")
    record_event(db, user.id, "view_metadata", "document", doc.id, "success", {})
    db.commit()
    return _doc_dict(db, doc, user)

@router.get("/documents/{document_id}/preview")
def preview_document(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    require_document_permission(db, doc, user, "read")
    path = storage_path / doc.storage_filename
    if not path.is_file():
        record_event(db, user.id, "preview", "document", doc.id, "error", {"reason": "missing storage file"}); db.commit()
        raise HTTPException(status_code=500, detail="Stored file is unavailable")
    content = path.read_bytes()
    actual_hash = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(actual_hash, doc.sha256):
        record_event(db, user.id, "file_integrity_check", "document", doc.id, "error", {"expected_sha256": doc.sha256, "actual_sha256": actual_hash})
        db.commit()
        raise HTTPException(status_code=500, detail="File integrity check failed. Preview blocked.")
    record_event(db, user.id, "preview", "document", doc.id, "success", {"sha256": actual_hash})
    db.commit()
    # Inline preview improves read-only workflows but cannot prevent screenshots or browser-level saving.
    safe_name = doc.original_filename.replace('"', "")
    return Response(content=content, media_type=doc.content_type,
                    headers={"Content-Disposition": f'inline; filename="{safe_name}"',
                             "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

@router.get("/documents/{document_id}/download")
def download_document(document_id: int, watermark: bool = True, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    require_document_permission(db, doc, user, "download")
    path = storage_path / doc.storage_filename
    if not path.is_file():
        record_event(db, user.id, "download", "document", doc.id, "error", {"reason": "missing storage file"}); db.commit()
        raise HTTPException(status_code=500, detail="Stored file is unavailable")
    content = path.read_bytes()
    actual_hash = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(actual_hash, doc.sha256):
        record_event(db, user.id, "file_integrity_check", "document", doc.id, "error", {"expected_sha256": doc.sha256, "actual_sha256": actual_hash})
        db.commit()
        raise HTTPException(status_code=500, detail="File integrity check failed. Download blocked.")
    filename = doc.original_filename
    media_type = doc.content_type
    if watermark:
        label = f"TRUSTVAULT CONFIDENTIAL - {user.email} - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        ext = Path(filename).suffix.lower()
        try:
            if ext == ".pdf": content = watermark_pdf(content, label)
            elif ext in (".png", ".jpg", ".jpeg"):
                content = watermark_image(content, label); filename = f"{Path(filename).stem}_watermarked.png"; media_type = "image/png"
            elif ext == ".txt": content = (f"{label}\n{'-'*50}\n".encode() + content)
        except Exception:
            record_event(db, user.id, "watermark_download", "document", doc.id, "error", {"reason": "watermark_failed"}); db.commit()
            raise HTTPException(status_code=500, detail="Could not create watermarked download")
    record_event(db, user.id, "download", "document", doc.id, "success", {"sha256": actual_hash, "watermarked": watermark})
    db.commit()
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename.replace(chr(34), "")}"', "X-Content-Type-Options": "nosniff"})

@router.patch("/documents/{document_id}")
def update_document(document_id: int, payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    require_document_permission(db, doc, user, "edit")
    allowed = {"title", "category"}
    if set(payload.keys()) - allowed:
        raise HTTPException(status_code=400, detail="Only title and category can be updated")
    if "title" in payload:
        doc.title = str(payload["title"]).strip()[:255] or doc.title
    if "category" in payload:
        doc.category = str(payload["category"]).strip()[:100] or "General"
    doc.updated_at = datetime.now(timezone.utc)
    record_event(db, user.id, "edit_metadata", "document", doc.id, "success", {"fields": sorted(payload.keys())})
    db.commit()
    db.refresh(doc)
    return _doc_dict(db, doc, user)

@router.delete("/documents/{document_id}")
def delete_document(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    if doc.owner_id != user.id:
        record_event(db, user.id, "delete", "document", doc.id, "denied", {})
        db.commit()
        raise HTTPException(status_code=403, detail="Only the document owner can delete this document")
    path = storage_path / doc.storage_filename
    version_rows = db.scalars(select(DocumentVersion).where(DocumentVersion.document_id == doc.id)).all()
    approval_rows = db.scalars(select(ApprovalRequest).where(ApprovalRequest.document_id == doc.id)).all()
    grant_rows = db.scalars(select(Grant).where(Grant.document_id == doc.id)).all()
    version_paths = [storage_path / item.storage_filename for item in version_rows]
    record_event(db, user.id, "delete", "document", doc.id, "success", {"title": doc.title, "sha256": doc.sha256, "version_count": len(version_rows)})
    for row in version_rows + approval_rows + grant_rows:
        db.delete(row)
    db.delete(doc)
    db.commit()
    for stored_path in [path, *version_paths]:
        if stored_path.exists(): stored_path.unlink()
    return {"message": "Document and its private version files deleted"}

@router.get("/documents/{document_id}/grants")
def get_grants(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    if doc.owner_id != user.id and not (active_grant(db, doc, user) and active_grant(db, doc, user).can_share):
        raise HTTPException(status_code=403, detail="Only the owner or a recipient with share permission can view grants")
    rows = db.scalars(select(Grant).where(Grant.document_id == doc.id, Grant.revoked_at.is_(None), or_(Grant.expires_at.is_(None), Grant.expires_at > datetime.now(timezone.utc)))).all()
    return [{"user_id": g.user_id, "email": g.user.email, "full_name": g.user.full_name,
             "permission": g.permission if g.permission != "none" else ("download" if g.can_download else "share" if g.can_share else "none"), "can_download": g.can_download, "can_share": g.can_share, "created_at": g.created_at, "expires_at": g.expires_at} for g in rows]

@router.post("/documents/{document_id}/grants")
def grant_access(document_id: int, payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    share_grant = active_grant(db, doc, user)
    if doc.owner_id != user.id and not (share_grant and share_grant.can_share):
        record_event(db, user.id, "grant_access", "document", doc.id, "denied", {})
        db.commit()
        raise HTTPException(status_code=403, detail="Only the owner or a recipient with share permission can grant access")
    if doc.requires_approval and doc.approval_status != "approved":
        record_event(db, user.id, "grant_access", "document", doc.id, "denied", {"reason": "approval_required", "approval_status": doc.approval_status})
        db.commit()
        raise HTTPException(status_code=409, detail="This document requires administrator approval before it can be shared")
    email = str(payload.get("email", "")).strip().lower()
    permission = payload.get("permission", "read")
    expires_raw = payload.get("expires_at")
    expires_at = None
    if expires_raw:
        try:
            expires_at = datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
            if expires_at.tzinfo is None: expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc): raise ValueError()
        except ValueError:
            raise HTTPException(status_code=400, detail="expires_at must be a future ISO-8601 date/time")
    if permission not in ("read", "edit", "download", "share"):
        raise HTTPException(status_code=400, detail="Permission must be read, edit, download, or share")
    recipient = db.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
    if not recipient:
        raise HTTPException(status_code=404, detail="Active recipient not found")
    if recipient.id == doc.owner_id:
        raise HTTPException(status_code=400, detail="The owner already has access")
    current = db.scalars(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == recipient.id,
                                               Grant.revoked_at.is_(None))).all()
    if current:
        current[-1].permission = permission if permission in ("read", "edit") else "none"
        current[-1].can_download = permission == "download"
        current[-1].can_share = permission == "share"
        current[-1].granted_by = user.id
        current[-1].expires_at = expires_at
        action = "change_permission"
    else:
        db.add(Grant(document_id=doc.id, user_id=recipient.id, permission=permission if permission in ("read", "edit") else "none", can_download=permission == "download", can_share=permission == "share", granted_by=user.id, expires_at=expires_at))
        action = "grant_access"
    record_event(db, user.id, action, "document", doc.id, "success",
                 {"recipient_id": recipient.id, "permission": permission, "expires_at": expires_at.isoformat() if expires_at else None})
    notify(db, user.id, recipient.email, "A TrustVault document was shared with you", f"{user.full_name} shared {doc.title!r} with you. Permission: {permission}." + (f" Access expires: {expires_at.isoformat()}" if expires_at else ""), "document", doc.id)
    db.commit()
    return {"message": "Access granted", "email": recipient.email, "permission": permission, "expires_at": expires_at}

@router.delete("/documents/{document_id}/grants/{user_id}")
def revoke_access(document_id: int, user_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    if doc.owner_id != user.id:
        record_event(db, user.id, "revoke_access", "document", doc.id, "denied", {})
        db.commit()
        raise HTTPException(status_code=403, detail="Only the document owner can revoke access")
    grants = db.scalars(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == user_id,
                                            Grant.revoked_at.is_(None))).all()
    if not grants:
        raise HTTPException(status_code=404, detail="Active grant not found")
    now = datetime.now(timezone.utc)
    for grant in grants:
        grant.revoked_at = now
    record_event(db, user.id, "revoke_access", "document", doc.id, "success", {"recipient_id": user_id})
    recipient = db.get(User, user_id)
    if recipient: notify(db, user.id, recipient.email, "TrustVault access revoked", f"Your access to {doc.title!r} was revoked by {user.full_name}.", "document", doc.id)
    db.commit()
    return {"message": "Access revoked"}

@router.get("/documents/{document_id}/audit")
def document_audit(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    if doc.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only the document owner can view document audit events")
    rows = db.scalars(select(AuditEvent).where(AuditEvent.resource_type == "document",
        AuditEvent.resource_id == str(doc.id)).order_by(AuditEvent.id.desc()).limit(200)).all()
    return [_audit_dict(e, db) for e in rows]

def _audit_dict(e, db=None):
    actor = db.get(User, e.actor_id) if db is not None and e.actor_id is not None else None
    return {"id": e.id, "actor_id": e.actor_id, "actor_email": actor.email if actor else None, "action": e.action, "resource_type": e.resource_type,
            "resource_id": e.resource_id, "outcome": e.outcome, "details": json.loads(e.details),
            "created_at": e.created_at, "previous_hash": e.previous_hash, "event_hash": e.event_hash}

@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.scalars(select(DeviceSession).where(DeviceSession.user_id == user.id)
                      .order_by(DeviceSession.created_at.desc()).limit(100)).all()
    return [{"id": row.id, "device_label": row.device_label, "user_agent": row.user_agent,
             "ip_address": row.ip_address, "created_at": row.created_at, "last_seen_at": row.last_seen_at,
             "revoked_at": row.revoked_at, "current": False} for row in rows]

@router.delete("/sessions/{session_id}")
def revoke_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    session = db.get(DeviceSession, session_id)
    if not session or session.user_id != user.id:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        record_event(db, user.id, "session_revoked", "session", session.id, "success", {"device": session.device_label})
        db.commit()
    return {"message": "Session revoked. Its token will be rejected on the next request."}

@router.post("/auth/logout")
def logout(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials | None = Depends(logout_bearer),
):
    # Revoke the server-side session so a copied token is rejected on its next request.
    if credentials:
        try:
            payload = decode_access_payload(credentials.credentials)
            session_id = payload.get("sid")
        except Exception:
            session_id = None
        if session_id:
            session = db.get(DeviceSession, session_id)
            if session and session.user_id == user.id and session.revoked_at is None:
                session.revoked_at = datetime.now(timezone.utc)
                record_event(db, user.id, "logout", "session", session.id, "success", {})
                db.commit()
    return {"message": "Signed out. This session has been revoked."}

@router.post("/documents/{document_id}/access-requests")
def create_access_request(document_id: int, payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    requested = str(payload.get("permission", "read")).lower()
    reason = str(payload.get("reason", ""))[:1000]
    if requested not in ("read", "edit", "download", "share"):
        raise HTTPException(status_code=400, detail="Permission must be read, edit, download, or share")
    if doc.owner_id == user.id or user.role == "admin":
        raise HTTPException(status_code=400, detail="You already have administrative or owner access")
    existing = db.scalar(select(AccessRequest.id).where(AccessRequest.document_id == doc.id,
        AccessRequest.requester_id == user.id, AccessRequest.status.in_(["pending", "otp_pending"])))
    if existing:
        raise HTTPException(status_code=409, detail="You already have a pending access request for this document")
    req = AccessRequest(document_id=doc.id, requester_id=user.id, requested_permission=requested, reason=reason)
    db.add(req); db.flush()
    owner = db.get(User, doc.owner_id)
    record_event(db, user.id, "access_request_created", "document", doc.id, "success",
                 {"request_id": req.id, "requested_permission": requested})
    if owner:
        notify(db, user.id, owner.email, "TrustVault access request",
               f"{user.full_name} ({user.email}) requested {requested} access to {doc.title!r}. Reason: {reason or 'Not provided'}. Review the request in TrustVault.", "document", doc.id)
    db.commit()
    return {"id": req.id, "status": req.status, "message": "Request sent to the document owner"}

def _access_request_dict(db, item):
    doc = db.get(Document, item.document_id)
    requester = db.get(User, item.requester_id)
    return {"id": item.id, "document_id": item.document_id, "document_title": doc.title if doc else "Deleted document",
            "owner_id": doc.owner_id if doc else None, "requester_id": item.requester_id,
            "requester_email": requester.email if requester else None, "requested_permission": item.requested_permission,
            "reason": item.reason, "status": item.status, "created_at": item.created_at, "decided_at": item.decided_at}

@router.get("/access-requests")
def list_access_requests(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == "admin":
        rows = db.scalars(select(AccessRequest).order_by(AccessRequest.created_at.desc()).limit(500)).all()
    else:
        owned_ids = select(Document.id).where(Document.owner_id == user.id)
        rows = db.scalars(select(AccessRequest).where(
            or_(AccessRequest.requester_id == user.id, AccessRequest.document_id.in_(owned_ids))
        ).order_by(AccessRequest.created_at.desc()).limit(500)).all()
    return [_access_request_dict(db, item) for item in rows]

@router.post("/access-requests/{request_id}/approve")
def begin_access_approval(request_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.get(AccessRequest, request_id)
    if not item: raise HTTPException(status_code=404, detail="Access request not found")
    doc = db.get(Document, item.document_id)
    if not doc or (doc.owner_id != user.id and user.role != "admin"):
        raise HTTPException(status_code=403, detail="Only the document owner can approve this request")
    if item.status != "pending": raise HTTPException(status_code=409, detail="Request is no longer pending")
    if not (settings.resend_api_key and settings.resend_from_email):
        raise HTTPException(status_code=503, detail="Configure the Resend email provider before approving access with OTP")
    code = f"{secrets.randbelow(1_000_000):06d}"
    item.otp_hash = hashlib.sha256(code.encode()).hexdigest()
    item.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    item.otp_attempts = 0; item.status = "otp_pending"
    sent = send_email(user.email, "TrustVault owner approval verification",
                      f"You requested approval of access to {doc.title!r}. Owner verification code: {code}. Expires in 5 minutes. If you did not initiate this approval, deny the request.")
    record_event(db, user.id, "access_approval_otp_sent", "document", doc.id,
                 "success" if sent else "error", {"request_id": item.id})
    db.commit()
    if not sent: raise HTTPException(status_code=503, detail="Could not send owner verification code")
    return {"message": "Verification code sent to the document owner's email", "request_id": item.id}

@router.post("/access-requests/{request_id}/verify")
def verify_access_approval(request_id: int, payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.get(AccessRequest, request_id)
    if not item: raise HTTPException(status_code=404, detail="Access request not found")
    doc = db.get(Document, item.document_id)
    if not doc or (doc.owner_id != user.id and user.role != "admin"):
        raise HTTPException(status_code=403, detail="Only the document owner can verify approval")
    if item.status != "otp_pending" or not item.otp_hash or not item.otp_expires_at:
        raise HTTPException(status_code=409, detail="Request is not awaiting OTP verification")
    expiry = item.otp_expires_at if item.otp_expires_at.tzinfo else item.otp_expires_at.replace(tzinfo=timezone.utc)
    code = str(payload.get("code", ""))
    if item.otp_attempts >= 5 or expiry <= datetime.now(timezone.utc) or not hmac.compare_digest(item.otp_hash, hashlib.sha256(code.encode()).hexdigest()):
        item.otp_attempts += 1
        if item.otp_attempts >= 5 or expiry <= datetime.now(timezone.utc):
            item.status = "expired"; item.otp_hash = None
        record_event(db, user.id, "access_approval_otp_denied", "document", doc.id, "denied", {"request_id": item.id})
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    requester = db.get(User, item.requester_id)
    if not requester or not requester.is_active:
        item.status = "denied"; item.otp_hash = None; db.commit()
        raise HTTPException(status_code=409, detail="Requester is inactive")
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    permission = item.requested_permission
    db.add(Grant(document_id=doc.id, user_id=requester.id,
                 permission=permission if permission in ("read", "edit") else "none",
                 can_download=permission == "download", can_share=permission == "share",
                 granted_by=user.id, expires_at=expires))
    item.status = "approved"; item.decided_at = datetime.now(timezone.utc); item.otp_hash = None
    record_event(db, user.id, "access_request_approved_by_otp", "document", doc.id, "success",
                 {"request_id": item.id, "recipient_id": requester.id, "permission": permission,
                  "expires_at": expires.isoformat()})
    notify(db, user.id, requester.email, "TrustVault temporary access approved",
           f"The owner approved {permission} access to {doc.title!r} for one hour.", "document", doc.id)
    db.commit()
    return {"message": "OTP verified. Temporary access granted for one hour.", "expires_at": expires}

@router.post("/access-requests/{request_id}/deny")
def deny_access_request(request_id: int, payload: dict | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.get(AccessRequest, request_id)
    if not item: raise HTTPException(status_code=404, detail="Access request not found")
    doc = db.get(Document, item.document_id)
    if not doc or (doc.owner_id != user.id and user.role != "admin"):
        raise HTTPException(status_code=403, detail="Only the document owner can deny this request")
    if item.status not in ("pending", "otp_pending"): raise HTTPException(status_code=409, detail="Request is no longer pending")
    item.status = "denied"; item.decided_at = datetime.now(timezone.utc); item.otp_hash = None
    record_event(db, user.id, "access_request_denied", "document", doc.id, "success",
                 {"request_id": item.id, "reason": str((payload or {}).get("reason", ""))[:500]})
    requester = db.get(User, item.requester_id)
    if requester: notify(db, user.id, requester.email, "TrustVault access request denied",
                         f"Your request for {doc.title!r} was denied by the owner.", "document", doc.id)
    db.commit()
    return {"message": "Access request denied"}

@router.get("/audit")
def audit_feed(limit: int = Query(100, ge=1, le=500), action: str | None = None, outcome: str | None = None,
               actor_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    stmt = select(AuditEvent)
    if action: stmt = stmt.where(AuditEvent.action.ilike(f"%{action[:80]}%"))
    if outcome in ("success", "denied", "error", "skipped_or_failed"): stmt = stmt.where(AuditEvent.outcome == outcome)
    if actor_id is not None: stmt = stmt.where(AuditEvent.actor_id == actor_id)
    rows = db.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit)).all()
    return [_audit_dict(e, db) for e in rows]

@router.get("/audit/verify")
def audit_verify(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    result = verify_chain(db)
    record_event(db, user.id, "audit_verify", "audit", None, "success", result)
    db.commit()
    return result

# ---- Extended workflows: integrity, version history, approvals, and richer audit ----
@router.get("/documents/{document_id}/integrity")
def document_integrity(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    require_document_permission(db, doc, user, "read")
    path = storage_path / doc.storage_filename
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    valid = actual is not None and hmac.compare_digest(actual, doc.sha256)
    record_event(db, user.id, "file_integrity_check", "document", doc.id, "success" if valid else "error",
                 {"expected_sha256": doc.sha256, "actual_sha256": actual})
    db.commit()
    return {"document_id": doc.id, "valid": valid, "expected_sha256": doc.sha256, "actual_sha256": actual}

@router.get("/documents/{document_id}/versions")
def list_versions(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    require_document_permission(db, doc, user, "read")
    rows = db.scalars(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version_number.desc())).all()
    return [{"id": v.id, "version_number": v.version_number, "original_filename": v.original_filename,
             "content_type": v.content_type, "size_bytes": v.size_bytes, "sha256": v.sha256,
             "created_by": v.created_by, "created_at": v.created_at, "note": v.note} for v in rows]

@router.post("/documents/{document_id}/versions")
async def upload_version(document_id: int, file: UploadFile = File(...), note: str = Form(""),
                         db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    require_document_permission(db, doc, user, "edit")
    original = _safe_filename(file.filename or doc.original_filename)
    ext = Path(original).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS: raise HTTPException(status_code=400, detail="Unsupported file type")
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES: raise HTTPException(status_code=413, detail=f"Maximum upload size is {settings.max_upload_mb} MB")
    _validate_content(ext, content, file.content_type or "")
    current_path = storage_path / doc.storage_filename
    if not current_path.is_file(): raise HTTPException(status_code=500, detail="Current stored file is missing")
    old_content = current_path.read_bytes()
    old_hash = hashlib.sha256(old_content).hexdigest()
    max_version = db.scalar(select(func.max(DocumentVersion.version_number)).where(DocumentVersion.document_id == doc.id)) or 0
    snapshot_name = uuid.uuid4().hex
    (storage_path / snapshot_name).write_bytes(old_content)
    db.add(DocumentVersion(document_id=doc.id, version_number=max_version + 1, storage_filename=snapshot_name,
        original_filename=doc.original_filename, content_type=doc.content_type, size_bytes=len(old_content),
        sha256=old_hash, created_by=user.id, note=(note or "Previous version before update")[:500]))
    current_path.write_bytes(content)
    doc.original_filename = original
    doc.content_type = next(iter(ALLOWED_TYPES[ext]))
    doc.size_bytes = len(content); doc.sha256 = hashlib.sha256(content).hexdigest(); doc.updated_at = datetime.now(timezone.utc)
    record_event(db, user.id, "document_new_version", "document", doc.id, "success",
                 {"version_number": max_version + 1, "sha256": doc.sha256, "note": note[:500]})
    for grant in db.scalars(select(Grant).where(Grant.document_id == doc.id, Grant.revoked_at.is_(None))).all():
        recipient = db.get(User, grant.user_id)
        if recipient and recipient.is_active:
            notify(db, user.id, recipient.email, "TrustVault document updated", f"A new version of {doc.title!r} is available.", "document", doc.id)
    db.commit(); db.refresh(doc)
    return {"message": "New version uploaded", "document": _doc_dict(db, doc, user)}

@router.post("/documents/{document_id}/versions/{version_id}/restore")
def restore_version(document_id: int, version_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id); require_document_permission(db, doc, user, "edit")
    version = db.get(DocumentVersion, version_id)
    if not version or version.document_id != doc.id: raise HTTPException(status_code=404, detail="Version not found")
    version_path = storage_path / version.storage_filename
    current_path = storage_path / doc.storage_filename
    if not version_path.is_file() or not current_path.is_file(): raise HTTPException(status_code=500, detail="Version file is missing")
    current_content = current_path.read_bytes()
    max_version = db.scalar(select(func.max(DocumentVersion.version_number)).where(DocumentVersion.document_id == doc.id)) or 0
    snapshot_name = uuid.uuid4().hex; (storage_path / snapshot_name).write_bytes(current_content)
    db.add(DocumentVersion(document_id=doc.id, version_number=max_version + 1, storage_filename=snapshot_name,
        original_filename=doc.original_filename, content_type=doc.content_type, size_bytes=len(current_content),
        sha256=hashlib.sha256(current_content).hexdigest(), created_by=user.id, note=f"Snapshot before restoring version {version.version_number}"))
    restored = version_path.read_bytes(); current_path.write_bytes(restored)
    doc.original_filename = version.original_filename; doc.content_type = version.content_type
    doc.size_bytes = len(restored); doc.sha256 = hashlib.sha256(restored).hexdigest(); doc.updated_at = datetime.now(timezone.utc)
    record_event(db, user.id, "document_version_restored", "document", doc.id, "success", {"version_id": version.id, "version_number": version.version_number})
    db.commit(); db.refresh(doc)
    return {"message": f"Restored version {version.version_number}", "document": _doc_dict(db, doc, user)}

@router.post("/documents/{document_id}/approval-request")
def request_approval(document_id: int, payload: dict | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = get_document_or_404(db, document_id)
    if doc.owner_id != user.id and user.role != "admin": raise HTTPException(status_code=403, detail="Only the owner can request approval")
    existing_pending = db.scalar(select(ApprovalRequest.id).where(ApprovalRequest.document_id == doc.id, ApprovalRequest.status == "pending"))
    if existing_pending:
        raise HTTPException(status_code=409, detail="An approval request is already pending")
    doc.requires_approval = True; doc.approval_status = "pending"
    request = ApprovalRequest(document_id=doc.id, requested_by=user.id, status="pending", note=str((payload or {}).get("note", ""))[:1000])
    db.add(request); db.flush()
    record_event(db, user.id, "approval_requested", "document", doc.id, "success", {"approval_request_id": request.id})
    db.commit()
    return {"message": "Approval requested", "status": "pending"}

@router.get("/approvals")
def list_approvals(status: str = "pending", db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    stmt = select(ApprovalRequest)
    if status in ("pending", "approved", "rejected"): stmt = stmt.where(ApprovalRequest.status == status)
    rows = db.scalars(stmt.order_by(ApprovalRequest.created_at.desc()).limit(500)).all()
    output = []
    for item in rows:
        doc = db.get(Document, item.document_id); requester = db.get(User, item.requested_by)
        reviewer = db.get(User, item.reviewed_by) if item.reviewed_by else None
        output.append({"id": item.id, "document_id": item.document_id, "document_title": doc.title if doc else "Deleted document",
            "requested_by": item.requested_by, "requester_email": requester.email if requester else None,
            "status": item.status, "note": item.note, "reviewer_note": item.reviewer_note,
            "reviewed_by": item.reviewed_by, "reviewer_email": reviewer.email if reviewer else None,
            "created_at": item.created_at, "reviewed_at": item.reviewed_at})
    return output

@router.patch("/approvals/{approval_id}")
def review_approval(approval_id: int, payload: dict, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    request = db.get(ApprovalRequest, approval_id)
    if not request: raise HTTPException(status_code=404, detail="Approval request not found")
    status = payload.get("status")
    if status not in ("approved", "rejected"): raise HTTPException(status_code=400, detail="status must be approved or rejected")
    if request.status != "pending": raise HTTPException(status_code=409, detail="This approval request has already been reviewed")
    doc = db.get(Document, request.document_id)
    if not doc: raise HTTPException(status_code=404, detail="Document not found")
    request.status = status; request.reviewed_by = admin.id; request.reviewed_at = datetime.now(timezone.utc)
    request.reviewer_note = str(payload.get("reviewer_note", ""))[:1000]
    # Latest decision governs whether sharing is allowed.
    doc.approval_status = status
    record_event(db, admin.id, f"approval_{status}", "document", doc.id, "success", {"approval_request_id": request.id, "reviewer_note": request.reviewer_note})
    owner = db.get(User, doc.owner_id)
    if owner: notify(db, admin.id, owner.email, f"TrustVault document approval {status}", f"Your document {doc.title!r} was {status}. {request.reviewer_note}", "document", doc.id)
    db.commit()
    return {"message": f"Approval {status}", "document_id": doc.id, "status": status}
