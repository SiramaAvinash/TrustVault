"""Bootstrap TrustVault tables from SQLAlchemy metadata.

This is the initial schema baseline for a fresh install and a no-op for tables
that already exist. Future schema changes should use explicit Alembic revisions.
"""
from alembic import op
from app.db.session import Base
from app import models  # noqa: F401

revision = "20261025_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    Base.metadata.create_all(bind=op.get_bind())


def downgrade():
    Base.metadata.drop_all(bind=op.get_bind())
