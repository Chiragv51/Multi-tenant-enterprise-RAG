"""IngestionJob — tracks the lifecycle of a background ingestion task.

status enum mirrors the Celery/RQ task states relevant to our system.
On permanent failure (attempts >= max_attempts), status = 'failed' and
the row is moved to a dead-letter view (implemented in T9).
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKeyConstraint, Integer, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, timestamp_now


class JobStatus(enum.StrEnum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    retrying = "retrying"


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"

    __table_args__ = (
        # Composite FK guard
        ForeignKeyConstraint(
            ["tenant_id", "document_id"],
            ["documents.tenant_id", "documents.id"],
            ondelete="CASCADE",
            name="fk_ingestion_jobs_document",
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
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="job_status"),
        nullable=False,
        server_default=JobStatus.pending.value,
    )
    # Number of attempted executions (for retry / dead-letter logic)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # Last error message; NULL when job succeeded. Never stores document text (AGENTS.md §3)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = timestamp_now()

    # Relationships
    document: Mapped["Document"] = relationship(  # noqa: F821
        back_populates="ingestion_jobs",
        foreign_keys="[IngestionJob.tenant_id, IngestionJob.document_id]",
    )
