from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.session import Base, engine
from app.models import User, Document, Grant, AuditEvent, DocumentVersion, ApprovalRequest, LoginOTP, DeviceSession, AccessRequest
from app.api.routes import router

# Development keeps a lightweight compatibility path for existing local SQLite projects.
# Production schema changes must be applied with `alembic upgrade head` before startup.
if settings.environment.lower() not in {"production", "prod"}:
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import inspect
    with engine.begin() as connection:
        inspector = inspect(engine)
        migrations = {
            "users": {"two_factor_enabled": "BOOLEAN NOT NULL DEFAULT 0", "google_sub": "VARCHAR(255) NULL"},
            "documents": {"requires_approval": "BOOLEAN NOT NULL DEFAULT 0", "approval_status": "VARCHAR(20) NOT NULL DEFAULT 'not_required'"},
            "document_grants": {"expires_at": "DATETIME NULL", "can_download": "BOOLEAN NOT NULL DEFAULT 0", "can_share": "BOOLEAN NOT NULL DEFAULT 0"},
        }
        for table, columns in migrations.items():
            existing = {col["name"] for col in inspector.get_columns(table)}
            for column, sql_type in columns.items():
                if column not in existing:
                    connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")
        connection.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_google_sub ON users (google_sub)")

app = FastAPI(title="TrustVault API", version="1.0.0",
              description="Secure document sharing with server-side authorization and a tamper-evident audit chain.")
configured_origins = [origin.strip().rstrip("/") for origin in settings.frontend_origin.split(",") if origin.strip()]
if settings.environment.lower() not in {"production", "prod"}:
    configured_origins.extend(["http://localhost:5173", "http://127.0.0.1:5173"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(set(configured_origins)),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(router)

@app.get("/")
def root():
    return {"message": "TrustVault API is running", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok"}
