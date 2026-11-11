"""Alembic env.py — reads DATABASE_URL from environment, supports async (asyncpg)."""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.core.config import get_settings

# ---------------------------------------------------------------------------
# Alembic Config object (gives access to alembic.ini values)
# ---------------------------------------------------------------------------
config = context.config

# Inject DATABASE_URL from environment so the ini file never contains creds.
_db_url = os.environ.get("DATABASE_URL") or get_settings().DATABASE_URL
# Alembic 1.x: set the url programmatically
config.set_main_option("sqlalchemy.url", _db_url)

# Logging setup from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Import *all* models so their metadata is populated before autogenerate.
# AGENTS.md rule: every new model file must be imported here.
# ---------------------------------------------------------------------------
from app.db.models import (  # noqa: E402, F401
    api_key,
    base,  # noqa: E402  (must come after sys.path setup)
    chunk,
    document,
    document_acl,
    group,
    ingestion_job,
    tenant,
    usage_event,
    user,
    user_group,
)

target_metadata = base.Base.metadata

# ---------------------------------------------------------------------------
# Offline mode — emit SQL to stdout without a live connection
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online mode — async engine so asyncpg driver works
# ---------------------------------------------------------------------------


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
