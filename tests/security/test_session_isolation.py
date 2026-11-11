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
6. Cross-tenant INSERT blocked: PostgreSQL RLS WITH CHECK rejects inserting rows for other tenants.
7. Cross-tenant UPDATE blocked: PostgreSQL RLS USING ensures updates targeting other tenants affect 0 rows.
8. Cross-tenant DELETE blocked: PostgreSQL RLS USING ensures deletes targeting other tenants affect 0 rows.
"""

import asyncio
import uuid

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError, ProgrammingError
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


# ==============================================================================
# 4. Cross-Tenant Write Isolation Tests (INSERT, UPDATE, DELETE)
# ==============================================================================


@pytest.mark.asyncio
async def test_cross_tenant_insert_blocked(
    pooled_session_factory,
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Under Tenant A context, inserting a record with Tenant B's tenant_id must fail.

    PostgreSQL RLS WITH CHECK policy rejects the insert with an InsufficientPrivilegeError.
    The transaction is cleanly rolled back.
    """
    tenant_a, tenant_b = tenant_ids
    unique_email = f"cross_insert_{uuid.uuid4().hex[:8]}@example.com"
    target_user_id = uuid.uuid4()

    async with pooled_session_factory() as session:
        await session.begin()
        await set_tenant_context(session, tenant_a)

        foreign_user = User(
            id=target_user_id,
            tenant_id=tenant_b,
            email=unique_email,
            role="employee",
        )
        session.add(foreign_user)

        with pytest.raises((ProgrammingError, DBAPIError)) as exc_info:
            await session.flush()

        err_str = str(exc_info.value).lower()
        assert "violates row-level security policy" in err_str
        await session.rollback()

    # Verify no record was inserted under Tenant B
    async with pooled_session_factory() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            user = await session.get(User, target_user_id)
            assert user is None


@pytest.mark.asyncio
async def test_cross_tenant_update_blocked(
    pooled_session_factory,
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Under Tenant A context, updating a record belonging to Tenant B must affect zero rows.

    PostgreSQL RLS USING clause filters out rows belonging to other tenants,
    causing the UPDATE statement to match 0 rows without mutating data.
    """
    tenant_a, tenant_b = tenant_ids
    target_user_id = uuid.uuid4()
    unique_email = f"target_update_{uuid.uuid4().hex[:8]}@example.com"

    # Step 1: Create a record belonging to Tenant B
    async with pooled_session_factory() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            user_b = User(
                id=target_user_id,
                tenant_id=tenant_b,
                email=unique_email,
                role="employee",
            )
            session.add(user_b)

    try:
        # Step 2: Under Tenant A context, attempt to update Tenant B's record
        async with pooled_session_factory() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                stmt = (
                    update(User).where(User.id == target_user_id).values(role="admin")
                )
                res = await session.execute(stmt)
                assert (
                    res.rowcount == 0
                ), f"Cross-tenant UPDATE affected {res.rowcount} rows! Expected 0."

        # Step 3: Re-read under Tenant B context and confirm original value remains unchanged
        async with pooled_session_factory() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_b)
                user_check = await session.get(User, target_user_id)
                assert user_check is not None
                assert (
                    user_check.role == "employee"
                ), f"User role was unexpectedly modified to '{user_check.role}'!"
    finally:
        # Cleanup: Remove the test record under Tenant B context
        async with pooled_session_factory() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_b)
                await session.execute(delete(User).where(User.id == target_user_id))


@pytest.mark.asyncio
async def test_cross_tenant_delete_blocked(
    pooled_session_factory,
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Under Tenant A context, deleting a record belonging to Tenant B must affect zero rows.

    PostgreSQL RLS USING clause filters out rows belonging to other tenants,
    causing the DELETE statement to match 0 rows without removing the record.
    """
    tenant_a, tenant_b = tenant_ids
    target_user_id = uuid.uuid4()
    unique_email = f"target_delete_{uuid.uuid4().hex[:8]}@example.com"

    # Step 1: Create a record belonging to Tenant B
    async with pooled_session_factory() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            user_b = User(
                id=target_user_id,
                tenant_id=tenant_b,
                email=unique_email,
                role="employee",
            )
            session.add(user_b)

    try:
        # Step 2: Under Tenant A context, attempt to delete Tenant B's record
        async with pooled_session_factory() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                stmt = delete(User).where(User.id == target_user_id)
                res = await session.execute(stmt)
                assert (
                    res.rowcount == 0
                ), f"Cross-tenant DELETE removed {res.rowcount} rows! Expected 0."

        # Step 3: Re-read under Tenant B context and confirm the record still exists
        async with pooled_session_factory() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_b)
                user_check = await session.get(User, target_user_id)
                assert user_check is not None, "User record was deleted cross-tenant!"
                assert user_check.email == unique_email
    finally:
        # Cleanup: Remove the test record under Tenant B context
        async with pooled_session_factory() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_b)
                await session.execute(delete(User).where(User.id == target_user_id))
