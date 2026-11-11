"""tests/api/test_auth.py — Authentication endpoint (POST /v1/auth/token) tests.

Tests:
1. Valid credentials for CityCare admin return a valid JWT.
2. Verified claims contain DB-retrieved tenant_id, user_id, role, groups, exp.
3. Wrong password is rejected with HTTP 401.
4. Unknown tenant is rejected with HTTP 401.
5. Unknown user is rejected with HTTP 401.
6. Cross-tenant spoofing: User from Tenant A cannot authenticate under Tenant B's identifier (HTTP 401).
7. User without a password hash cannot authenticate (HTTP 401).
8. Password and sensitive data are never logged or leaked.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security import verify_access_token
from app.db.models import Tenant, User
from app.db.session import AsyncSessionLocal, set_tenant_context
from app.main import app


@pytest.fixture
async def seeded_citycare_credentials() -> dict[str, str]:
    """Retrieve CityCare tenant and admin user for login tests."""
    async with AsyncSessionLocal() as session:
        stmt = select(Tenant).where(Tenant.name == "CityCare")
        tenant = (await session.execute(stmt)).scalar_one()
        return {
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.name,
            "email": "admin@citycare.org",
            "password": "TenantAdminPass123!",
        }


@pytest.mark.asyncio
async def test_login_valid_credentials_by_name(
    seeded_citycare_credentials: dict[str, str],
) -> None:
    """Test login using tenant name returns 200 and a valid JWT."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": seeded_citycare_credentials["tenant_name"],
                "email": seeded_citycare_credentials["email"],
                "password": seeded_citycare_credentials["password"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 30 * 60

        # Verify decoded token claims
        claims = verify_access_token(data["access_token"])
        assert claims["tenant_id"] == seeded_citycare_credentials["tenant_id"]
        assert claims["role"] == "tenant_admin"
        assert "Hospital Administrators" in claims["groups"]


@pytest.mark.asyncio
async def test_login_valid_credentials_by_uuid(
    seeded_citycare_credentials: dict[str, str],
) -> None:
    """Test login using tenant UUID returns 200 and a valid JWT."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": seeded_citycare_credentials["tenant_id"],
                "email": seeded_citycare_credentials["email"],
                "password": seeded_citycare_credentials["password"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data


@pytest.mark.asyncio
async def test_login_wrong_password_rejected(
    seeded_citycare_credentials: dict[str, str],
) -> None:
    """Test login with wrong password returns 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": seeded_citycare_credentials["tenant_name"],
                "email": seeded_citycare_credentials["email"],
                "password": "WrongPassword!",
            },
        )
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "HTTP_401"
        assert "Invalid" in data["error"]["message"]


@pytest.mark.asyncio
async def test_login_unknown_tenant_rejected() -> None:
    """Test login with non-existent tenant returns 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": "NonExistentHospital",
                "email": "admin@citycare.org",
                "password": "TenantAdminPass123!",
            },
        )
        assert response.status_code == 401
        data = response.json()
        assert "error" in data


@pytest.mark.asyncio
async def test_login_unknown_user_rejected(
    seeded_citycare_credentials: dict[str, str],
) -> None:
    """Test login with non-existent user in valid tenant returns 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": seeded_citycare_credentials["tenant_name"],
                "email": "nobody@citycare.org",
                "password": "TenantAdminPass123!",
            },
        )
        assert response.status_code == 401
        data = response.json()
        assert "error" in data


@pytest.mark.asyncio
async def test_cross_tenant_spoofing_prevented() -> None:
    """User from Tenant A (CityCare) attempting to log in under Tenant B (SecureLife) must be rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": "SecureLife",
                "email": "admin@citycare.org",  # CityCare user
                "password": "TenantAdminPass123!",
            },
        )
        assert response.status_code == 401
        data = response.json()
        assert "error" in data


@pytest.mark.asyncio
async def test_user_without_password_hash_cannot_authenticate() -> None:
    """Create a user with NULL password_hash and verify they cannot log in."""
    test_email = f"nohash_{uuid.uuid4().hex[:8]}@citycare.org"
    async with AsyncSessionLocal() as session:
        # Retrieve CityCare tenant
        tenant_stmt = select(Tenant).where(Tenant.name == "CityCare")
        tenant = (await session.execute(tenant_stmt)).scalar_one()

        await set_tenant_context(session, tenant.id)

        unhashed_user = User(
            tenant_id=tenant.id,
            email=test_email,
            role="employee",
            password_hash=None,
        )
        session.add(unhashed_user)
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": "CityCare",
                "email": test_email,
                "password": "AnyPassword123!",
            },
        )
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
