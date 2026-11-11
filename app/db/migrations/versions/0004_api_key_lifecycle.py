"""0004_api_key_lifecycle

Add name and revoked_at columns to api_keys table for T3c API key management and lifecycle tracking.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("name", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "api_keys",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("api_keys", "revoked_at")
    op.drop_column("api_keys", "name")
