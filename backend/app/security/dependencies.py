from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import jwt
from datetime import datetime, timezone
from app.db.session import get_db
from app.models.entities import User, DeviceSession
from app.security.tokens import decode_access_payload

bearer = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = decode_access_payload(credentials.credentials)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User is inactive or unavailable")
    session_id = payload.get("sid")
    if session_id:
        session = db.get(DeviceSession, session_id)
        if not session or session.user_id != user.id or session.revoked_at is not None:
            raise HTTPException(status_code=401, detail="Session has been revoked")
        session.last_seen_at = datetime.now(timezone.utc)
        db.commit()
    return user

def require_admin(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user
