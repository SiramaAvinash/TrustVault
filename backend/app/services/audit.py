import hashlib, json
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.entities import AuditEvent

ZERO_HASH = "0" * 64

def _canonical(actor_id, action, resource_type, resource_id, outcome, details, created_at, previous_hash):
    from datetime import timezone
    # SQLite can return timezone-aware timestamps as naive datetimes; canonicalize both forms to UTC.
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    else:
        created_at = created_at.astimezone(timezone.utc)
    payload = {
        "actor_id": actor_id, "action": action, "resource_type": resource_type,
        "resource_id": resource_id, "outcome": outcome, "details": details,
        "created_at": created_at.isoformat(), "previous_hash": previous_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def record_event(db: Session, actor_id, action, resource_type, resource_id=None, outcome="success", details=None):
    previous = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    previous_hash = previous.event_hash if previous else ZERO_HASH
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    raw = _canonical(actor_id, action, resource_type, str(resource_id) if resource_id is not None else None, outcome, details_json, now, previous_hash)
    event_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    event = AuditEvent(actor_id=actor_id, action=action, resource_type=resource_type,
                       resource_id=str(resource_id) if resource_id is not None else None,
                       outcome=outcome, details=details_json, created_at=now,
                       previous_hash=previous_hash, event_hash=event_hash)
    db.add(event)
    db.flush()
    return event

def verify_chain(db: Session):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())).all()
    previous_hash = ZERO_HASH
    for event in events:
        if event.previous_hash != previous_hash:
            return {"valid": False, "failed_event_id": event.id, "checked": len(events)}
        raw = _canonical(event.actor_id, event.action, event.resource_type, event.resource_id,
                         event.outcome, event.details, event.created_at, event.previous_hash)
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if expected != event.event_hash:
            return {"valid": False, "failed_event_id": event.id, "checked": len(events)}
        previous_hash = event.event_hash
    return {"valid": True, "failed_event_id": None, "checked": len(events)}
