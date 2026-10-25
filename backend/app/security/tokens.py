from datetime import datetime, timedelta, timezone
import jwt
from app.core.config import settings

ALGORITHM = "HS256"

def create_access_token(user_id: int, session_id: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "iat": now, "exp": now + timedelta(minutes=settings.access_token_minutes)}
    if session_id:
        payload["sid"] = session_id
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)

def decode_access_payload(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])

def decode_access_token(token: str) -> int:
    payload = decode_access_payload(token)
    return int(payload["sub"])
