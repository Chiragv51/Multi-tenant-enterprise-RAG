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
