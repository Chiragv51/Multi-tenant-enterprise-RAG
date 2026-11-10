"""app/db/models/__init__.py — re-exports all ORM models.

Importing this package is sufficient to register all models with Base.metadata.
env.py imports from here so autogenerate sees the full schema.
"""

from app.db.models.api_key import APIKey
from app.db.models.base import Base
from app.db.models.chunk import Chunk
from app.db.models.document import Document, DocumentStatus
from app.db.models.document_acl import DocumentACL, PrincipalType
from app.db.models.group import Group
from app.db.models.ingestion_job import IngestionJob, JobStatus
from app.db.models.tenant import Tenant
from app.db.models.usage_event import UsageEvent
from app.db.models.user import User
from app.db.models.user_group import UserGroup

__all__ = [
    "Base",
    "Tenant",
    "User",
    "Group",
    "UserGroup",
    "Document",
    "DocumentStatus",
    "DocumentACL",
    "PrincipalType",
    "Chunk",
    "IngestionJob",
    "JobStatus",
    "UsageEvent",
    "APIKey",
]
