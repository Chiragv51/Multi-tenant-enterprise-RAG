"""Tenant model — the root of every multi-tenant object."""

import uuid
from datetime import datetime

from sqlalchemy import Integer, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, timestamp_now


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan: Mapped[str] = mapped_column(String(64), nullable=False, server_default="free")
    rate_limit: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="60"
    )
    created_at: Mapped[datetime] = timestamp_now()

    # Relationships (back-populated from child tables)
    users: Mapped[list["User"]] = relationship(back_populates="tenant")  # noqa: F821
    groups: Mapped[list["Group"]] = relationship(back_populates="tenant")  # noqa: F821
    documents: Mapped[list["Document"]] = relationship(  # noqa: F821
        back_populates="tenant"
    )
