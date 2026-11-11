"""app/api/v1/auth.py — Authentication endpoints.

Implements POST /v1/auth/token:
- Resolves tenant identifier (name or UUID) strictly as a hint.
- Scopes DB session to that tenant using set_tenant_context().
- Authenticates user against stored bcrypt password hash.
- Enforces that users without a password hash cannot authenticate.
- Extracts DB-verified claims: tenant_id, user_id, role (mapped to coarse JWT role), and groups.
- Issues signed Bearer JWT token.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    map_db_role_to_jwt_role,
    verify_password,
)
from app.db.models import Group, Tenant, User, UserGroup
from app.db.session import get_db, set_tenant_context

logger = logging.getLogger("auth")

router = APIRouter(tags=["Authentication"])


class TokenRequest(BaseModel):
    """Login request payload."""

    tenant: str = Field(
        ...,
        description="Tenant identifier: unique tenant name or tenant UUID.",
        min_length=1,
    )
    email: EmailStr = Field(..., description="User's email address.")
    password: str = Field(..., description="User's plain password.", min_length=1)


class TokenResponse(BaseModel):
    """OAuth2 / JWT Token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Obtain a tenant-scoped JWT access token via email/password",
)
async def login_for_access_token(
    credentials: TokenRequest,
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate email/password for a given tenant hint and issue a signed JWT."""
    # 1. Lookup tenant (unscoped query on tenants table which has no RLS)
    tenant_hint = credentials.tenant.strip()
    tenant_stmt = select(Tenant)
    try:
        tenant_uuid = uuid.UUID(tenant_hint)
        tenant_stmt = tenant_stmt.where(
            (Tenant.id == tenant_uuid) | (Tenant.name == tenant_hint)
        )
    except ValueError:
        tenant_stmt = tenant_stmt.where(Tenant.name == tenant_hint)

    res = await session.execute(tenant_stmt)
    tenant = res.scalar_one_or_none()

    if not tenant:
        # Uniform 401 response to prevent tenant enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid tenant, email, or password.",
        )

    # 2. Scope the transaction to the candidate tenant so RLS allows reading user
    await set_tenant_context(session, tenant.id)

    # 3. Lookup user within that specific tenant
    clean_email = credentials.email.strip().lower()
    user_stmt = select(User).where(
        User.tenant_id == tenant.id,
        User.email == clean_email,
    )
    user_res = await session.execute(user_stmt)
    user = user_res.scalar_one_or_none()

    # Reject if user does not exist or has no password hash
    if not user or not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid tenant, email, or password.",
        )

    # 4. Verify password hash using constant-time bcrypt verification
    if not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid tenant, email, or password.",
        )

    # 5. Query user's group names within this tenant
    groups_stmt = (
        select(Group.name)
        .join(UserGroup, UserGroup.group_id == Group.id)
        .where(
            UserGroup.tenant_id == tenant.id,
            UserGroup.user_id == user.id,
            Group.tenant_id == tenant.id,
        )
        .order_by(Group.name)
    )
    groups = list((await session.scalars(groups_stmt)).all())

    # 6. Map granular DB role to JWT RBAC role
    jwt_role = map_db_role_to_jwt_role(user.role)

    # 7. Issue JWT token with DB-verified claims
    token = create_access_token(
        user_id=user.id,
        tenant_id=tenant.id,
        role=jwt_role,
        groups=groups,
    )

    settings = get_settings()
    logger.info(
        "User authenticated successfully (tenant_id=%s, user_id=%s, role=%s)",
        tenant.id,
        user.id,
        jwt_role,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
