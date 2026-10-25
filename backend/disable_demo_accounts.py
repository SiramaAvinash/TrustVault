"""Deactivate legacy sample accounts from earlier starter versions, preserving document history."""
from sqlalchemy import select
from app.db.session import SessionLocal, Base, engine
from app.main import app as _app  # run schema migrations for existing databases
from app.models.entities import User, Grant
from datetime import datetime, timezone

LEGACY = {"admin@trustvault.local", "owner@trustvault.local", "viewer@trustvault.local"}
def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        users = db.scalars(select(User).where(User.email.in_(LEGACY))).all()
        now = datetime.now(timezone.utc)
        for user in users:
            user.is_active = False
            grants = db.query(Grant).filter(Grant.user_id == user.id, Grant.revoked_at.is_(None)).all()
            for grant in grants:
                grant.revoked_at = now
        db.commit()
        print(f"Deactivated {len(users)} legacy demo account(s). Existing records were preserved.")
    finally: db.close()
if __name__ == "__main__": main()
