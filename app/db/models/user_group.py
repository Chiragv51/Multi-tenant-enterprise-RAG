"""UserGroup — many-to-many join table between users and groups.

Composite PK: (tenant_id, user_id, group_id).
Both user_id and group_id FKs are composite (tenant_id + id) to prevent
a user from one tenant being placed in a group from another tenant.
"""

import uuid

from sqlalchemy import ForeignKeyConstraint, PrimaryKeyConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base


class UserGroup(Base):
    __tablename__ = "user_groups"

    __table_args__ = (
        # Composite PK — (tenant_id, user_id, group_id)
        PrimaryKeyConstraint("tenant_id", "user_id", "group_id", name="pk_user_groups"),
        # Composite FK to users(tenant_id, id) — prevents cross-tenant membership
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["users.tenant_id", "users.id"],
            ondelete="CASCADE",
            name="fk_user_groups_user",
        ),
        # Composite FK to groups(tenant_id, id)
        ForeignKeyConstraint(
            ["tenant_id", "group_id"],
            ["groups.tenant_id", "groups.id"],
            ondelete="CASCADE",
            name="fk_user_groups_group",
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    group_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Relationships
    user: Mapped["User"] = relationship(  # noqa: F821
        back_populates="group_memberships"
    )
    group: Mapped["Group"] = relationship(back_populates="members")  # noqa: F821
