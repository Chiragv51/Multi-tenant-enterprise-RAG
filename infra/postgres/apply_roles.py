"""Apply PostgreSQL roles and permissions from infra/postgres/roles.sql.

Used during local setup, Docker initialization, and CI pipeline setup.
Connects as the privileged schema owner (rag_user) to create the application
runtime role (rag_app), grant necessary DML privileges, and securely set
its password using safe psycopg2.sql Identifier and Literal composition without embedding secrets in SQL.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import psycopg2  # noqa: E402
from psycopg2 import sql  # noqa: E402

from app.core.config import get_settings  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("apply_roles")


def apply_roles() -> None:
    settings = get_settings()
    roles_sql_path = Path(__file__).resolve().parent / "roles.sql"

    if not roles_sql_path.is_file():
        raise FileNotFoundError(f"roles.sql not found at {roles_sql_path}")

    logger.info(
        "Connecting to %s:%s/%s as %s...",
        settings.POSTGRES_HOST,
        settings.POSTGRES_PORT,
        settings.POSTGRES_DB,
        settings.POSTGRES_USER,
    )
    conn = psycopg2.connect(
        host=settings.POSTGRES_HOST,
        port=settings.POSTGRES_PORT,
        user=settings.POSTGRES_USER,
        password=settings.POSTGRES_PASSWORD,
        dbname=settings.POSTGRES_DB,
    )
    conn.autocommit = True
    try:
        with open(roles_sql_path, encoding="utf-8") as f:
            sql_script = f.read()

        # Verify role consistency with infrastructure definition
        if settings.POSTGRES_APP_USER != "rag_app":
            raise ValueError(
                f"Configured POSTGRES_APP_USER '{settings.POSTGRES_APP_USER}' does not match "
                f"the 'rag_app' role defined in roles.sql."
            )

        with conn.cursor() as cur:
            # 1. Execute role creation and DML permission grants
            cur.execute(sql_script)

            # 2. Set runtime role password safely using psycopg2.sql Identifier and Literal composition
            alter_role_stmt = sql.SQL(
                "ALTER ROLE {role} WITH PASSWORD {password}"
            ).format(
                role=sql.Identifier(settings.POSTGRES_APP_USER),
                password=sql.Literal(settings.POSTGRES_APP_PASSWORD),
            )
            cur.execute(alter_role_stmt)

        logger.info(
            "Database roles, privileges, and runtime credentials applied successfully."
        )
    finally:
        conn.close()


if __name__ == "__main__":
    apply_roles()
