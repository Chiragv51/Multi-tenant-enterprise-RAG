"""tests/test_migrations.py

Smoke-test: runs `alembic upgrade head` and `alembic downgrade base` against a
real, ephemeral Postgres container (pgvector/pgvector:pg16) spun up by
testcontainers. The cycle is run twice to prove idempotency.

Requirements: Docker daemon must be running.
Runs in CI via the `migration-check` job in ci.yml.
"""

import subprocess
import sys

import pytest

try:
    from testcontainers.community.postgres import PostgresContainer
except ImportError:
    from testcontainers.postgres import PostgresContainer

POSTGRES_IMAGE = "pgvector/pgvector:pg16"


@pytest.fixture(scope="module")
def pg_url() -> str:  # type: ignore[return]
    """Start an ephemeral Postgres container and yield its sync URL."""
    with PostgresContainer(image=POSTGRES_IMAGE) as pg:
        # testcontainers returns a psycopg2 URL; Alembic needs asyncpg
        sync_url: str = pg.get_connection_url()
        async_url = sync_url.replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        ).replace("postgresql://", "postgresql+asyncpg://")
        yield async_url


def _alembic(cmd: list[str], db_url: str) -> None:
    """Run an alembic CLI subcommand with DATABASE_URL injected."""
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *cmd],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "DATABASE_URL": db_url},
    )
    if result.returncode != 0:
        raise AssertionError(
            f"alembic {' '.join(cmd)} failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )


def test_migration_upgrade_downgrade_cycle(pg_url: str) -> None:
    """upgrade head → downgrade base → upgrade head must all succeed."""
    _alembic(["upgrade", "head"], pg_url)
    _alembic(["downgrade", "base"], pg_url)
    # Second upgrade proves downgrade was truly clean
    _alembic(["upgrade", "head"], pg_url)
