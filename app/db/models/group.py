"""Group model — a named collection of users within a tenant."""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, timestamp_now


class Group(Base):
    __tablename__ = "groups"

    __table_args__ = (
        # Composite unique so (tenant_id, id) can be referenced as a composite FK
        UniqueConstraint("tenant_id", "id", name="uq_groups_tenant_id"),
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
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = timestamp_now()

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="groups")  # noqa: F821
    members: Mapped[list["UserGroup"]] = relationship(  # noqa: F821
        back_populates="group"
    )
