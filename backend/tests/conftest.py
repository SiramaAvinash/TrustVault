import os
os.environ["DATABASE_URL"] = "sqlite:///./test_trustvault.db"
os.environ["STORAGE_DIR"] = "./test_storage"
os.environ["JWT_SECRET"] = "test-secret-key-only-long-enough-32chars"
os.environ["MAX_UPLOAD_MB"] = "1"

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import Base, engine, SessionLocal
from app.models.entities import User
from app.security.passwords import hash_password

@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for email, name, role, pw in [
        ("admin@example.com", "Admin", "admin", "AdminPass123!"),
        ("owner@example.com", "Owner One", "owner", "OwnerPass123!"),
        ("viewer@example.com", "Viewer One", "viewer", "ViewerPass123!"),
        ("other@example.com", "Other User", "viewer", "OtherPass123!"),
    ]:
        db.add(User(email=email, full_name=name, role=role, password_hash=hash_password(pw)))
    db.commit()
    db.close()
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)
