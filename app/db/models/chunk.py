"""Chunk model — a text segment from a Document, with its embedding vector.

Design decisions (see docs/ADR-02-chunking.md):
- embedding: vector(384) for bge-small-en-v1.5 (1024 dims for bge-m3).
  Dimension is set to 384 here; adjust to 1024 if switching embedding model.
- tsv: GENERATED ALWAYS AS tsvector column — maintained by Postgres, never by Python.
  This powers BM25 / full-text search (FR4) without double-maintenance.
- HNSW vector index is deferred to T12 (after ingestion pipeline is working).
- UNIQUE (document_id, version, chunk_index) is the idempotency key (FR6):
  re-running ingestion on the same file version never creates duplicates.
"""

import uuid
from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Computed,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, timestamp_now

# Embedding dimension — must match the chosen embedding model.
# bge-small-en-v1.5 → 384 | bge-m3 → 1024
EMBEDDING_DIM = 384


class Chunk(Base):
    __tablename__ = "chunks"

    __table_args__ = (
        # Composite FK guard: document must belong to same tenant
        ForeignKeyConstraint(
            ["tenant_id", "document_id"],
            ["documents.tenant_id", "documents.id"],
            ondelete="CASCADE",
            name="fk_chunks_document",
        ),
        # Idempotency key: same (document, version, position) → same chunk
        UniqueConstraint(
            "document_id",
            "version",
            "chunk_index",
            name="uq_chunks_idempotency",
        ),
        # Hot-path index for retrieval: filter by tenant + document before vector scan
        Index("ix_chunks_tenant_document", "tenant_id", "document_id"),
        # GIN index for BM25 / full-text search (FR4)
        Index("ix_chunks_tsv", "tsv", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # Tenant isolation
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    document_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Matches Document.version at time of ingestion
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    # Zero-based position within the document
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)

    content: Mapped[str] = mapped_column(Text, nullable=False)

    # pgvector column — dimension must match EMBEDDING_DIM
    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)

    # PostgreSQL automatically generates and stores this column.
    # Python application must never insert or update its value.
    tsv: Mapped[str | None] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('english', content)", persisted=True),
        nullable=True,
    )

    page: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Arbitrary per-chunk metadata (e.g., headings path, section title)
    chunk_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, name="metadata"
    )

    created_at: Mapped[datetime] = timestamp_now()

    # Relationships
    document: Mapped["Document"] = relationship(  # noqa: F821
        back_populates="chunks",
        foreign_keys="[Chunk.tenant_id, Chunk.document_id]",
    )
