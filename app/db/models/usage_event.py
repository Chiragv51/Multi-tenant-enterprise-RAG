"""UsageEvent — immutable per-request cost/token audit log.

Append-only: rows are never updated.
Used for per-tenant billing and abuse detection (FR7, T17).
Never stores query text or answer text (AGENTS.md §3 — no PII in logs/DB).
"""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Float, ForeignKey, Integer, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base, timestamp_now


class UsageEvent(Base):
    __tablename__ = "usage_events"

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
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # Token counts for cost accounting
    query_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    answer_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    # Estimated USD cost (may be 0.0 for open-source models)
    cost: Mapped[float] = mapped_column(Float, nullable=False, server_default="0.0")
    # End-to-end latency in milliseconds (excluding first-token streaming)
    latency_ms: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    created_at: Mapped[datetime] = timestamp_now()
