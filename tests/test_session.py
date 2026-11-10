import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal, engine, get_db


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
