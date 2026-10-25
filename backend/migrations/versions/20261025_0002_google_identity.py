"""Add Google identity mapping to existing user tables."""
from alembic import op
import sqlalchemy as sa

revision = "20261025_0002"
down_revision = "20261025_0001"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("users")}
    if "google_sub" not in columns:
        op.add_column("users", sa.Column("google_sub", sa.String(length=255), nullable=True))
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("users")}
    if "ix_users_google_sub" not in indexes:
        op.create_index("ix_users_google_sub", "users", ["google_sub"], unique=True)


def downgrade():
    bind = op.get_bind()
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("users")}
    if "ix_users_google_sub" in indexes:
        op.drop_index("ix_users_google_sub", table_name="users")
    columns = {column["name"] for column in sa.inspect(bind).get_columns("users")}
    if "google_sub" in columns:
        op.drop_column("users", "google_sub")
