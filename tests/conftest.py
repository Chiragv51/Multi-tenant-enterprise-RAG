"""tests/conftest.py — Global test configuration and async cleanup fixtures."""

import pytest

from app.db.session import engine


@pytest.fixture(autouse=True)
async def cleanup_db_engine():
    """Dispose engine connections after each test to prevent event-loop-closed errors."""
    yield
    await engine.dispose()
