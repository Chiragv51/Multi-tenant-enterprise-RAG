"""DocumentACL — per-document access control entries.

principal_type controls who the principal_id refers to:
  - 'user'   → principal_id = users.id
  - 'group'  → principal_id = groups.id
  - 'tenant' → principal_id is NULL (all users of the tenant can access)

AGENTS.md rule: ACL is evaluated INSIDE the DB query, never post-fetch in Python.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKeyConstraint, Index, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, timestamp_now


class PrincipalType(enum.StrEnum):
    user = "user"
    group = "group"
    tenant = "tenant"


class DocumentACL(Base):
    __tablename__ = "document_acl"

    __table_args__ = (
        # Composite FK ensures document belongs to same tenant (cross-tenant mismatch guard)
        ForeignKeyConstraint(
            ["tenant_id", "document_id"],
            ["documents.tenant_id", "documents.id"],
            ondelete="CASCADE",
            name="fk_document_acl_document",
        ),
        # Retrieval hot-path index: given a document, find all matching ACL entries fast
        Index(
            "ix_document_acl_lookup",
            "document_id",
            "principal_type",
            "principal_id",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    document_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    principal_type: Mapped[PrincipalType] = mapped_column(
        Enum(PrincipalType, name="principal_type"),
        nullable=False,
    )
    # NULL means tenant-wide access (principal_type == 'tenant')
    principal_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    created_at: Mapped[datetime] = timestamp_now()

    # Relationships
    document: Mapped["Document"] = relationship(  # noqa: F821
        back_populates="acl_entries",
        foreign_keys="[DocumentACL.tenant_id, DocumentACL.document_id]",
    )
