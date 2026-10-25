from fastapi import HTTPException
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.entities import Document, Grant, User, AuditEvent

def get_document_or_404(db: Session, document_id: int) -> Document:
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc

def active_grant(db: Session, doc: Document, user: User):
    grants = db.scalars(select(Grant).where(
        Grant.document_id == doc.id, Grant.user_id == user.id, Grant.revoked_at.is_(None)
    ).order_by(Grant.id.desc())).all()
    now = datetime.now(timezone.utc)
    for grant in grants:
        if grant.expires_at:
            expiry = grant.expires_at if grant.expires_at.tzinfo else grant.expires_at.replace(tzinfo=timezone.utc)
            if expiry <= now:
                continue
        return grant
    return None

def permission_for(db: Session, doc: Document, user: User) -> str | None:
    if doc.owner_id == user.id:
        return "owner"
    grant = active_grant(db, doc, user)
    if not grant:
        return None
    if grant.permission == "edit":
        return "edit"
    if grant.permission == "read":
        return "read"
    if grant.can_download and grant.can_share:
        return "download+share"
    if grant.can_download:
        return "download"
    if grant.can_share:
        return "share"
    return grant.permission

def require_document_permission(db: Session, doc: Document, user: User, needed="read"):
    if doc.owner_id == user.id:
        return "owner"
    grant = active_grant(db, doc, user)
    allowed = False
    if grant:
        if needed in ("read", "metadata"):
            allowed = grant.permission in ("read", "edit", "download", "share") or grant.can_download or grant.can_share
        elif needed == "edit":
            allowed = grant.permission == "edit"
        elif needed == "download":
            allowed = grant.permission == "edit" or grant.can_download
        elif needed == "share":
            allowed = grant.can_share
    if not allowed:
        from app.services.audit import record_event
        action = f"document_{needed}_denied"
        now = datetime.now(timezone.utc)
        recent_alert = db.scalar(select(AuditEvent.id).where(
            AuditEvent.actor_id == user.id, AuditEvent.action == action,
            AuditEvent.resource_type == "document", AuditEvent.resource_id == str(doc.id),
            AuditEvent.created_at >= now - timedelta(minutes=10)
        ).limit(1))
        record_event(db, user.id, action, "document", doc.id, "denied",
                     {"document_title": doc.title, "alert_deduplicated_window_minutes": 10})
        owner = db.get(User, doc.owner_id)
        if owner and not recent_alert:
            from app.services.notifications import notify
            notify(db, user.id, owner.email, "TrustVault alert: unauthorized document access",
                   f"TrustVault denied {user.email} from performing {needed} on your document {doc.title!r}. The attempt was recorded at {now.isoformat()}. Review Access Requests and Audit Trail. Repeated alerts for this same user/action/document are grouped for 10 minutes.",
                   "document", doc.id)
        db.commit()
        raise HTTPException(status_code=403, detail=f"You do not have permission to {needed} this document. The owner has been alerted where email notifications are configured.")
    return permission_for(db, doc, user)
