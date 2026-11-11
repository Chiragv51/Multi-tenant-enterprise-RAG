"""Apply PostgreSQL roles and permissions from infra/postgres/roles.sql.

Used during local setup, Docker initialization, and CI pipeline setup.
Connects as the privileged schema owner (rag_user) to create the application
runtime role (rag_app) and grant necessary DML privileges.
"""

import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import psycopg2  # noqa: E402

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
            sql = f.read()
        with conn.cursor() as cur:
            cur.execute(sql)
        logger.info("Database roles and permissions applied successfully.")
    finally:
        conn.close()


if __name__ == "__main__":
    apply_roles()
