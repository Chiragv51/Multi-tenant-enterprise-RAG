"""Enable and force tenant isolation using PostgreSQL RLS."""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "users",
    "groups",
    "user_groups",
    "documents",
    "document_acl",
    "chunks",
    "ingestion_jobs",
    "usage_events",
    "api_keys",
)


def upgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')

        op.execute(f"""
            CREATE POLICY tenant_isolation ON "{table}"
            USING (
                tenant_id = NULLIF(
                    current_setting('app.tenant_id', true), ''
                )::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(
                    current_setting('app.tenant_id', true), ''
                )::uuid
            )
            """)


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
