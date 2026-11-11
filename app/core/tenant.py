"""app/core/tenant.py — Typed TenantContext representation.

Represents verified, request-scoped tenant identity derived strictly from
cryptographically verified authentication (e.g. Bearer JWT).
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict


class TenantContext(BaseModel):
    """Verified tenant identity context attached to request.state.tenant_context."""

    model_config = ConfigDict(frozen=True)

    tenant_id: uuid.UUID
    user_id: uuid.UUID
    role: str
    groups: list[str]
