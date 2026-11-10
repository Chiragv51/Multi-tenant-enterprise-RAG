"""Document model — a file uploaded by a Tenant Admin.

status enum drives the ingestion state machine:
  pending → indexed | failed
  indexed → deleted (soft-delete via status flag)
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, Integer, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, timestamp_now


class DocumentStatus(str, enum.Enum):
    pending = "pending"
    indexed = "indexed"
    failed = "failed"
    deleted = "deleted"


class Document(Base):
    __tablename__ = "documents"

    __table_args__ = (
        # Composite unique so (tenant_id, id) is a valid composite FK target
        UniqueConstraint("tenant_id", "id", name="uq_documents_tenant_id"),
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
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    # SHA-256 hex of raw file bytes — used for idempotent re-indexing (FR6)
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Monotonically increasing; bumped on every content change
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    status: Mapped[DocumentStatus] = mapped_column(
        Enum(DocumentStatus, name="document_status"),
        nullable=False,
        server_default=DocumentStatus.pending.value,
    )
    created_at: Mapped[datetime] = timestamp_now()

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="documents")  # noqa: F821
    chunks: Mapped[list["Chunk"]] = relationship(  # noqa: F821
        back_populates="document"
    )
    acl_entries: Mapped[list["DocumentACL"]] = relationship(  # noqa: F821
        back_populates="document"
    )
    ingestion_jobs: Mapped[list["IngestionJob"]] = relationship(  # noqa: F821
        back_populates="document"
    )
