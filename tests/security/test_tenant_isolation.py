"""PostgreSQL Row-Level Security (RLS) integration tests.

Verifies strict tenant isolation using the non-superuser application role (`rag_app`).
The `rag_app` role has `NOSUPERUSER` and `NOBYPASSRLS`, ensuring that PostgreSQL
enforces RLS policies at the database engine level.

Test Scenarios:
1. Missing tenant context exposes 0 rows across all tenant-scoped tables.
2. Tenant A cannot SELECT Tenant B data.
3. Tenant A cannot INSERT data with Tenant B's tenant_id (RLS WITH CHECK violation).
4. Tenant A cannot UPDATE Tenant B data.
5. Tenant A cannot DELETE Tenant B data.
6. Application helper `set_tenant_context` works properly within a transaction.
"""

import uuid

import pytest
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.db.models import Chunk, Document, DocumentStatus, Group, Tenant, User
from app.db.session import set_tenant_context

settings = get_settings()

# Engine using the non-superuser, non-bypassrls application role with NullPool to prevent event-loop conflicts
app_engine = create_async_engine(
    settings.APP_DATABASE_URL,
    echo=False,
    poolclass=NullPool,
)
AppSessionLocal = async_sessionmaker(
    bind=app_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


@pytest.fixture
async def tenant_ids() -> tuple[uuid.UUID, uuid.UUID]:
    """Retrieve CityCare and SecureLife tenant IDs from the database."""
    async with AppSessionLocal() as session:
        stmt = select(Tenant.id, Tenant.name).where(
            Tenant.name.in_(["CityCare", "SecureLife"])
        )
        res = await session.execute(stmt)
        tenants = {name: tid for tid, name in res.all()}
        assert "CityCare" in tenants, "Seed data missing: CityCare tenant not found."
        assert (
            "SecureLife" in tenants
        ), "Seed data missing: SecureLife tenant not found."
        return tenants["CityCare"], tenants["SecureLife"]


@pytest.mark.asyncio
async def test_missing_tenant_context_exposes_no_rows():
    """Without setting app.tenant_id, a non-superuser role must see 0 tenant rows."""
    async with AppSessionLocal() as session:
        # All tenant-scoped tables must return 0 rows
        for table in [
            "users",
            "groups",
            "user_groups",
            "documents",
            "document_acl",
            "chunks",
            "ingestion_jobs",
            "usage_events",
            "api_keys",
        ]:
            res = await session.execute(text(f'SELECT count(*) FROM "{table}";'))
            count = res.scalar()
            assert (
                count == 0
            ), f"Leak detected: Table '{table}' exposed {count} rows without tenant context!"


@pytest.mark.asyncio
async def test_tenant_a_cannot_select_tenant_b_data(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
):
    """Tenant A can only select Tenant A rows; Tenant B rows are completely invisible."""
    tenant_a, tenant_b = tenant_ids

    # Query as Tenant A
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)

            # Check documents
            res = await session.execute(select(Document))
            docs_a = res.scalars().all()
            assert len(docs_a) > 0, "Tenant A should see its own seeded documents"
            for doc in docs_a:
                assert doc.tenant_id == tenant_a, "Cross-tenant leak in documents!"

            # Check users
            res = await session.execute(select(User))
            users_a = res.scalars().all()
            assert len(users_a) > 0
            for u in users_a:
                assert u.tenant_id == tenant_a, "Cross-tenant leak in users!"

            # Check groups
            res = await session.execute(select(Group))
            groups_a = res.scalars().all()
            assert len(groups_a) > 0
            for g in groups_a:
                assert g.tenant_id == tenant_a, "Cross-tenant leak in groups!"

            # Directly attempting to query Tenant B's doc by ID returns None
            res = await session.execute(
                select(Document).where(Document.tenant_id == tenant_b)
            )
            assert (
                res.first() is None
            ), "Tenant A queried Tenant B documents and got results!"

    # Query as Tenant B
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            res = await session.execute(select(Document))
            docs_b = res.scalars().all()
            assert len(docs_b) > 0
            for doc in docs_b:
                assert doc.tenant_id == tenant_b, "Tenant B saw non-Tenant B documents!"


@pytest.mark.asyncio
async def test_tenant_a_cannot_insert_data_for_tenant_b(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
):
    """Attempting to insert a row with tenant_b_id under tenant_a context must fail RLS WITH CHECK."""
    tenant_a, tenant_b = tenant_ids

    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)

            # Tenant A tries to forge an insert for Tenant B
            with pytest.raises(DBAPIError) as exc_info:
                await session.execute(
                    insert(Document).values(
                        tenant_id=tenant_b,
                        title="Forged Document for Tenant B",
                        source_hash="fake_hash",
                        version=1,
                        status=DocumentStatus.pending,
                    )
                )
            assert "row-level security policy" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_tenant_a_cannot_update_data_for_tenant_b(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
):
    """Tenant A attempting to update Tenant B data affects 0 rows due to RLS filter."""
    tenant_a, tenant_b = tenant_ids

    # 1. Fetch Tenant B's document title under Tenant B context
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            res = await session.execute(
                select(Document).where(Document.tenant_id == tenant_b)
            )
            doc_b = res.scalars().first()
            assert doc_b is not None
            original_title = doc_b.title
            doc_b_id = doc_b.id

    # 2. Attempt update under Tenant A context
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)

            result = await session.execute(
                update(Document)
                .where(Document.id == doc_b_id)
                .values(title="Hacked by Tenant A")
            )
            # RLS ensures row is not matched
            assert result.rowcount == 0

    # 3. Verify under Tenant B that the document is completely unmodified
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            res = await session.execute(select(Document).where(Document.id == doc_b_id))
            doc_b = res.scalars().first()
            assert doc_b is not None
            assert (
                doc_b.title == original_title
            ), "Tenant B document was modified by Tenant A!"


@pytest.mark.asyncio
async def test_tenant_a_cannot_delete_data_for_tenant_b(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
):
    """Tenant A attempting to delete Tenant B data affects 0 rows."""
    tenant_a, tenant_b = tenant_ids

    # 1. Identify Tenant B's document
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            res = await session.execute(
                select(Document).where(Document.tenant_id == tenant_b)
            )
            doc_b = res.scalars().first()
            assert doc_b is not None
            doc_b_id = doc_b.id

    # 2. Attempt deletion under Tenant A context
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            result = await session.execute(
                delete(Document).where(Document.id == doc_b_id)
            )
            assert result.rowcount == 0

    # 3. Verify under Tenant B that the document still exists
    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            res = await session.execute(select(Document).where(Document.id == doc_b_id))
            doc_b = res.scalars().first()
            assert doc_b is not None, "Tenant B document was deleted by Tenant A!"


@pytest.mark.asyncio
async def test_chunk_isolation(tenant_ids: tuple[uuid.UUID, uuid.UUID]):
    """Chunks are also strictly isolated by RLS."""
    tenant_a, tenant_b = tenant_ids

    async with AppSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            res = await session.execute(select(Chunk))
            chunks_a = res.scalars().all()
            assert len(chunks_a) > 0, "Tenant A should see its chunks"
            for chunk in chunks_a:
                assert chunk.tenant_id == tenant_a

            # Direct search for Tenant B chunks returns empty
            res = await session.execute(
                select(Chunk).where(Chunk.tenant_id == tenant_b)
            )
            assert res.first() is None
