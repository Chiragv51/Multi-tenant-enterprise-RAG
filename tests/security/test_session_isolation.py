"""tests/security/test_session_isolation.py — PostgreSQL RLS & Connection Pool Safety Tests.

Verifies:
1. Missing tenant context returns zero tenant-scoped rows under non-superuser role (rag_app).
2. Tenant A cannot read Tenant B data.
3. Sequential pooled requests: alternating requests on the same connection pool
   do not leak transaction-local tenant context.
4. Concurrent isolation: concurrent tasks for different tenants running on the same pool
   strictly isolate rows without cross-tenant pollution.
5. Database role security: proves runtime role 'rag_app' is NOSUPERUSER, NOBYPASSRLS,
   and does not own tenant tables.
"""

import asyncio
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.db.models import Tenant, User
from app.db.session import set_tenant_context

settings = get_settings()


@pytest.fixture
async def pooled_session_factory():
    """Create a real connection-pooled sessionmaker scoped to the test event loop."""
    engine = create_async_engine(
        settings.APP_DATABASE_URL,
        echo=False,
        pool_size=5,
        max_overflow=5,
    )
    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    yield session_factory
    await engine.dispose()


@pytest.fixture
async def tenant_ids(pooled_session_factory) -> tuple[uuid.UUID, uuid.UUID]:
    """Retrieve CityCare and SecureLife tenant IDs."""
    async with pooled_session_factory() as session:
        stmt = select(Tenant.id, Tenant.name).where(
            Tenant.name.in_(["CityCare", "SecureLife"])
        )
        res = (await session.execute(stmt)).all()
        id_map = {name: t_id for t_id, name in res}
        return id_map["CityCare"], id_map["SecureLife"]


# ==============================================================================
# 1. Database Role Security Hardening Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_database_role_is_non_superuser_and_no_bypassrls(
    pooled_session_factory,
) -> None:
    """Assert runtime connection role (rag_app) has NOSUPERUSER and NOBYPASSRLS in PostgreSQL."""
    async with pooled_session_factory() as session:
        # Check current user and privileges from pg_roles
        res = await session.execute(
            text(
                "SELECT rolname, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
        )
        row = res.one()
        current_role, is_superuser, bypass_rls = row

        assert (
            current_role == "rag_app"
        ), f"Expected connected role 'rag_app', got '{current_role}'"
        assert (
            is_superuser is False
        ), "Security violation: rag_app must NOT be a superuser!"
        assert (
            bypass_rls is False
        ), "Security violation: rag_app must NOT have BYPASSRLS!"


@pytest.mark.asyncio
async def test_application_role_does_not_own_tables(
    pooled_session_factory,
) -> None:
    """Assert runtime role (rag_app) is not the owner of tenant tables."""
    async with pooled_session_factory() as session:
        res = await session.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'users'")
        )
        table_owner = res.scalar_one()
        assert (
            table_owner != "rag_app"
        ), "Security violation: rag_app must not own the users table!"
        assert (
            table_owner == "rag_user"
        ), f"Expected schema owner 'rag_user', got '{table_owner}'"


# ==============================================================================
# 2. Sequential Connection Pool Isolation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_sequential_requests_on_shared_pool_do_not_leak_context(
    pooled_session_factory,
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Sequential requests on the same connection pool must never leak app.tenant_id."""
    tenant_a, tenant_b = tenant_ids

    # Request 1: Tenant A context
    async with pooled_session_factory() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            users_a = (await session.scalars(select(User))).all()
            assert len(users_a) > 0
            assert all(u.tenant_id == tenant_a for u in users_a)

    # Request 2: No tenant context on a recycled connection from pool
    # RLS must return 0 rows
    async with pooled_session_factory() as session:
        users_unscoped = (await session.scalars(select(User))).all()
        assert len(users_unscoped) == 0, "Leaked context: unscoped query returned rows!"

    # Request 3: Tenant B context
    async with pooled_session_factory() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            users_b = (await session.scalars(select(User))).all()
            assert len(users_b) > 0
            assert all(u.tenant_id == tenant_b for u in users_b)
            assert not any(u.tenant_id == tenant_a for u in users_b)


# ==============================================================================
# 3. Concurrent Pool Isolation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_concurrent_tenant_queries_isolated(
    pooled_session_factory,
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Multiple concurrent queries for different tenants running on shared pool must remain strictly isolated."""
    tenant_a, tenant_b = tenant_ids

    async def execute_tenant_query(
        target_tenant: uuid.UUID, other_tenant: uuid.UUID
    ) -> None:
        async with pooled_session_factory() as session:
            async with session.begin():
                await set_tenant_context(session, target_tenant)
                # Introduce slight async delay to interleave execution with other concurrent tasks
                await asyncio.sleep(0.02)
                users = (await session.scalars(select(User))).all()
                assert len(users) > 0
                assert all(u.tenant_id == target_tenant for u in users)
                assert not any(u.tenant_id == other_tenant for u in users)

    # Run 10 concurrent requests alternating between Tenant A and Tenant B
    tasks = []
    for i in range(10):
        t_target = tenant_a if i % 2 == 0 else tenant_b
        t_other = tenant_b if i % 2 == 0 else tenant_a
        tasks.append(execute_tenant_query(t_target, t_other))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, Exception):
            raise res
