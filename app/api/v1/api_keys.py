"""app/api/v1/api_keys.py — API key management endpoints.

Allows tenant administrators to create, list, revoke, and delete API keys for machine-to-machine auth.
All operations require valid JWT authentication with tenant_admin authorization.
All database operations use the authenticated tenant context with PostgreSQL RLS.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_key
from app.core.tenant import TenantContext
from app.db.models import APIKey
from app.db.session import get_current_tenant_db

logger = logging.getLogger("api_keys")

router = APIRouter(prefix="/api-keys", tags=["API Keys"])


def require_tenant_admin(request: Request) -> TenantContext:
    """Verify that the request is authenticated by a tenant administrator via JWT."""
    ctx: TenantContext | None = getattr(request.state, "tenant_context", None)
    if not ctx:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    if ctx.principal_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API keys cannot perform API key management operations.",
        )
    if ctx.role not in ("tenant_admin", "platform_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant administrator authorization required.",
        )
    return ctx


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(
        default="default",
        min_length=1,
        max_length=255,
        description="Descriptive name or label for the API key",
    )


class CreateAPIKeyResponse(BaseModel):
    id: uuid.UUID
    name: str | None
    api_key: str = Field(
        ...,
        description="Plaintext API key. Displayed ONLY once upon creation.",
    )
    created_at: datetime


class APIKeyItemResponse(BaseModel):
    id: uuid.UUID
    name: str | None
    created_at: datetime
    revoked_at: datetime | None = None
    is_active: bool


class RevokeAPIKeyResponse(BaseModel):
    id: uuid.UUID
    revoked: bool
    revoked_at: datetime


@router.post(
    "",
    response_model=CreateAPIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new API key for the authenticated tenant",
)
async def create_tenant_api_key(
    body: CreateAPIKeyRequest,
    ctx: TenantContext = Depends(require_tenant_admin),
    session: AsyncSession = Depends(get_current_tenant_db),
) -> CreateAPIKeyResponse:
    """Generate a new machine-to-machine API key.

    Returns the plaintext key once. Stored in DB only as SHA-256 hash.
    """
    raw_key, key_hash = generate_api_key(ctx.tenant_id)

    api_key = APIKey(
        tenant_id=ctx.tenant_id,
        name=body.name.strip(),
        key_hash=key_hash,
    )
    session.add(api_key)
    await session.flush()

    logger.info(
        "API key created (id=%s, tenant_id=%s, name=%s)",
        api_key.id,
        ctx.tenant_id,
        api_key.name,
    )

    return CreateAPIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        api_key=raw_key,
        created_at=api_key.created_at,
    )


@router.get(
    "",
    response_model=list[APIKeyItemResponse],
    summary="List all API keys for the authenticated tenant",
)
async def list_tenant_api_keys(
    ctx: TenantContext = Depends(require_tenant_admin),
    session: AsyncSession = Depends(get_current_tenant_db),
) -> list[APIKeyItemResponse]:
    """List API keys without exposing plaintext or hashes."""
    stmt = (
        select(APIKey)
        .where(APIKey.tenant_id == ctx.tenant_id)
        .order_by(APIKey.created_at.desc())
    )
    keys = (await session.scalars(stmt)).all()
    return [
        APIKeyItemResponse(
            id=k.id,
            name=k.name,
            created_at=k.created_at,
            revoked_at=k.revoked_at,
            is_active=k.revoked_at is None,
        )
        for k in keys
    ]


@router.post(
    "/{key_id}/revoke",
    response_model=RevokeAPIKeyResponse,
    summary="Revoke an API key immediately",
)
async def revoke_tenant_api_key(
    key_id: uuid.UUID,
    ctx: TenantContext = Depends(require_tenant_admin),
    session: AsyncSession = Depends(get_current_tenant_db),
) -> RevokeAPIKeyResponse:
    """Revoke an API key so it stops authenticating immediately."""
    stmt = select(APIKey).where(
        APIKey.id == key_id,
        APIKey.tenant_id == ctx.tenant_id,
    )
    api_key = (await session.execute(stmt)).scalar_one_or_none()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found.",
        )

    now = datetime.now(UTC)
    api_key.revoked_at = now
    await session.flush()

    logger.info(
        "API key revoked (id=%s, tenant_id=%s)",
        api_key.id,
        ctx.tenant_id,
    )

    return RevokeAPIKeyResponse(
        id=api_key.id,
        revoked=True,
        revoked_at=now,
    )


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an API key record permanently",
)
async def delete_tenant_api_key(
    key_id: uuid.UUID,
    ctx: TenantContext = Depends(require_tenant_admin),
    session: AsyncSession = Depends(get_current_tenant_db),
) -> Response:
    """Permanently delete an API key."""
    stmt = select(APIKey).where(
        APIKey.id == key_id,
        APIKey.tenant_id == ctx.tenant_id,
    )
    api_key = (await session.execute(stmt)).scalar_one_or_none()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found.",
        )

    await session.delete(api_key)
    await session.flush()

    logger.info(
        "API key deleted (id=%s, tenant_id=%s)",
        key_id,
        ctx.tenant_id,
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
