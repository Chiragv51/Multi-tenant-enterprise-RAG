"""User model — belongs to exactly one tenant."""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, timestamp_now


class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        # Composite unique so (tenant_id, id) can be used as a composite FK target
        # from child tables — prevents cross-tenant ID reuse attacks.
        UniqueConstraint("tenant_id", "id", name="uq_users_tenant_id"),
        # Email must be unique within a tenant (not globally)
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default="employee"
    )
    created_at: Mapped[datetime] = timestamp_now()

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="users")  # noqa: F821
    group_memberships: Mapped[list["UserGroup"]] = relationship(  # noqa: F821
        back_populates="user"
    )
