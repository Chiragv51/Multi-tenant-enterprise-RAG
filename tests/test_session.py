import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import (
    AsyncSessionLocal,
    engine,
    get_db,
    get_tenant_db,
    set_tenant_context,
)


@pytest.mark.asyncio
async def test_get_db_yields_async_session():
    generator = get_db()
    session = await anext(generator)
    try:
        assert isinstance(session, AsyncSession)
        assert session.bind == engine
    finally:
        await generator.aclose()


@pytest.mark.asyncio
async def test_session_factory_settings():
    assert AsyncSessionLocal.kw.get("expire_on_commit") is False
    assert AsyncSessionLocal.kw.get("autoflush") is False
    assert AsyncSessionLocal.class_ == AsyncSession


@pytest.mark.asyncio
async def test_set_tenant_context_validation():
    # Test invalid string format
    with pytest.raises(ValueError, match="is not a valid UUID"):
        async with AsyncSessionLocal() as session:
            await set_tenant_context(session, "not-a-valid-uuid")

    # Test invalid type
    with pytest.raises(TypeError, match="tenant_id must be a UUID or string"):
        async with AsyncSessionLocal() as session:
            await set_tenant_context(session, 12345)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_get_tenant_db_yields_session():
    test_id = uuid.uuid4()
    generator = get_tenant_db(test_id)
    session = await anext(generator)
    try:
        assert isinstance(session, AsyncSession)
    finally:
        await generator.aclose()


def test_runtime_engine_uses_rag_app_role():
    """Assert that runtime engine connects as the non-superuser rag_app role, never rag_user."""
    engine_url = engine.url
    assert engine_url.username == "rag_app", (
        f"Critical security violation: Runtime engine is connecting as '{engine_url.username}', "
        "expected 'rag_app'! Superusers bypass PostgreSQL Row-Level Security."
    )
    assert (
        engine_url.username != "rag_user"
    ), "Critical security violation: Runtime engine must NEVER connect as the privileged migration owner 'rag_user'!"
