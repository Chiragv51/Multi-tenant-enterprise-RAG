"""Async SQLAlchemy database engine and session dependency with tenant context."""

import uuid
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.APP_DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def set_tenant_context(
    session: AsyncSession,
    tenant_id: uuid.UUID | str,
) -> None:
    """Set transaction-local tenant context for PostgreSQL Row-Level Security (RLS).

    Uses `SELECT set_config('app.tenant_id', :tenant_id, true)` where is_local=true
    ensures the setting is scoped strictly to the current transaction.

    Validates tenant_id format before setting to prevent SQL injection or malformed UUID errors.
    Never pass an unverified client-supplied tenant ID to this function.
    """
    if isinstance(tenant_id, str):
        try:
            parsed_id = uuid.UUID(tenant_id)
        except ValueError as err:
            raise ValueError(
                f"Invalid tenant_id format: '{tenant_id}' is not a valid UUID."
            ) from err
    elif isinstance(tenant_id, uuid.UUID):
        parsed_id = tenant_id
    else:
        raise TypeError(
            f"tenant_id must be a UUID or string, got {type(tenant_id).__name__}"
        )

    await session.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(parsed_id)},
    )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Provide an async database session for a request without tenant context."""
    async with AsyncSessionLocal() as session:
        yield session


async def get_tenant_db(
    tenant_id: uuid.UUID | str,
) -> AsyncGenerator[AsyncSession, None]:
    """Provide an async database session with verified tenant context applied.

    The tenant_id MUST be verified by authentication middleware or JWT verification
    before being passed to this dependency.
    """
    async with AsyncSessionLocal() as session:
        await set_tenant_context(session, tenant_id)
        yield session


async def close_db() -> None:
    """Dispose the database connection pool during application shutdown."""
    await engine.dispose()
