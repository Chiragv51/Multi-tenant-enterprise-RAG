import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tenant import TenantContext
from app.db.session import (
    AsyncSessionLocal,
    engine,
    get_current_tenant_db,
    get_db,
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
async def test_get_current_tenant_db_missing_context_raises_403():
    """get_current_tenant_db must raise HTTP 403 if request.state.tenant_context is missing."""
    mock_request = MagicMock()
    mock_request.state = MagicMock(spec=[])  # No tenant_context

    with pytest.raises(HTTPException) as exc_info:
        generator = get_current_tenant_db(mock_request)
        await anext(generator)

    assert exc_info.value.status_code == 403
    assert "missing" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_get_current_tenant_db_scopes_session_and_cleans_up():
    """get_current_tenant_db must scope the session to verified context and reset on exit."""
    test_tenant_id = uuid.uuid4()
    mock_request = MagicMock()
    mock_request.state.tenant_context = TenantContext(
        tenant_id=test_tenant_id,
        user_id=uuid.uuid4(),
        role="employee",
        groups=[],
    )

    generator = get_current_tenant_db(mock_request)
    session = await anext(generator)
    try:
        assert isinstance(session, AsyncSession)
        # Verify app.tenant_id was set inside the transaction
        res = await session.execute(
            text("SELECT current_setting('app.tenant_id', true)")
        )
        assert res.scalar_one() == str(test_tenant_id)
    finally:
        await generator.aclose()

    # Verify that in a separate connection from the pool, app.tenant_id is NOT leaked
    async with AsyncSessionLocal() as clean_session:
        res = await clean_session.execute(
            text("SELECT current_setting('app.tenant_id', true)")
        )
        val = res.scalar_one()
        assert val == "" or val is None


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
