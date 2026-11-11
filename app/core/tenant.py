"""app/core/tenant.py — Typed TenantContext representation.

Represents verified, request-scoped tenant identity derived strictly from
cryptographically verified authentication (Bearer JWT or API Key).
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TenantContext(BaseModel):
    """Verified tenant identity context attached to request.state.tenant_context."""

    model_config = ConfigDict(frozen=True)

    tenant_id: uuid.UUID
    user_id: uuid.UUID | None = None
    role: str = "service"
    groups: list[str] = Field(default_factory=list)
    principal_type: Literal["user", "service"] = "user"
    api_key_id: uuid.UUID | None = None

    @property
    def is_service(self) -> bool:
        """Return True if principal is an authenticated machine/service API key."""
        return self.principal_type == "service"

    @property
    def is_user(self) -> bool:
        """Return True if principal is an authenticated human user."""
        return self.principal_type == "user"
