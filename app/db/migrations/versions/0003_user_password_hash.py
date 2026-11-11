"""0003_user_password_hash

Add nullable password_hash column to users table for T3b email/password authentication.
Existing users without a password hash cannot authenticate.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_hash", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "password_hash")
