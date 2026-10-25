"""Create the first TrustVault administrator without hard-coded credentials."""
import getpass
from sqlalchemy import select
from app.db.session import Base, engine, SessionLocal
from app.main import app as _app  # run schema migrations for existing databases
from app.models.entities import User
from app.security.passwords import hash_password


def main():
    Base.metadata.create_all(bind=engine)
    email = input("Administrator email: ").strip().lower()
    name = input("Administrator full name: ").strip()
    password = getpass.getpass("Password (12+ chars, upper/lower/number): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm: raise SystemExit("Passwords do not match.")
    if len(password) < 12 or not any(c.islower() for c in password) or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
        raise SystemExit("Use at least 12 characters with uppercase, lowercase, and a number.")
    db = SessionLocal()
    try:
        existing = db.scalar(select(User).where(User.email == email))
        if existing:
            existing.role = "admin"; existing.is_active = True
            if name: existing.full_name = name
            existing.password_hash = hash_password(password)
            print("Existing account promoted to administrator and password updated.")
        else:
            db.add(User(email=email, full_name=name or email.split("@")[0], role="admin", password_hash=hash_password(password), is_active=True))
            print("Administrator account created.")
        db.commit()
        print("Sign in with the email and password you just entered. No default credentials are created.")
    finally: db.close()

if __name__ == "__main__": main()
