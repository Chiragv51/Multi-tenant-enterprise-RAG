"""SQLAlchemy declarative base and shared column helpers."""

from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, MappedColumn, mapped_column


class Base(DeclarativeBase):
    """Single shared declarative base for all ORM models."""

    pass


def timestamp_now() -> MappedColumn[datetime]:
    """Reusable created_at column: timestamptz, server default = now()."""
    return mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
