"""tests/api/test_auth.py — Authentication endpoint (POST /v1/auth/token) tests.

Ticket T3 Hardening:
1. Valid credentials for CityCare admin return a valid JWT.
2. Verified claims contain DB-retrieved tenant_id, user_id, role, groups, exp, iat.
3. Wrong password is rejected with HTTP 401.
4. Unknown tenant is rejected with HTTP 401.
5. Unknown user is rejected with HTTP 401.
6. Cross-tenant spoofing: User from Tenant A cannot authenticate under Tenant B's identifier (HTTP 401).
7. User without a password hash cannot authenticate (HTTP 401).
8. Password byte limits: passwords exceeding 72 UTF-8 bytes are rejected (HTTP 422).
9. Multibyte passwords exceeding 72 UTF-8 bytes are rejected (HTTP 422).
10. Constant-time mitigation: uniform error messages across unknown tenant, unknown user, and bad password.
"""

from __future__ import annotations

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


@pytest.mark.asyncio
async def test_login_password_exceeding_72_bytes_rejected(
    seeded_citycare_credentials: dict[str, str],
) -> None:
    """Password exceeding 72 UTF-8 bytes must return 422 validation error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": seeded_citycare_credentials["tenant_name"],
                "email": seeded_citycare_credentials["email"],
                "password": "A" * 73,
            },
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"
        assert "72" in str(data["error"]["message"])


@pytest.mark.asyncio
async def test_login_multibyte_password_exceeding_72_bytes_rejected(
    seeded_citycare_credentials: dict[str, str],
) -> None:
    """Multibyte Unicode password exceeding 72 UTF-8 bytes must return 422."""
    # '€' is 3 bytes in UTF-8; 25 chars = 75 bytes
    too_many_bytes = "€" * 25
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": seeded_citycare_credentials["tenant_name"],
                "email": seeded_citycare_credentials["email"],
                "password": too_many_bytes,
            },
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_login_uniform_error_message_across_scenarios(
    seeded_citycare_credentials: dict[str, str],
) -> None:
    """Unknown tenant, unknown user, and wrong password must return identical generic error messages."""
    scenarios = [
        # 1. Unknown tenant
        {
            "tenant": "GhostTenant",
            "email": "admin@citycare.org",
            "password": "Pass123!",
        },
        # 2. Unknown user in valid tenant
        {
            "tenant": seeded_citycare_credentials["tenant_name"],
            "email": "nonexistent@citycare.org",
            "password": "Pass123!",
        },
        # 3. Wrong password for valid user
        {
            "tenant": seeded_citycare_credentials["tenant_name"],
            "email": seeded_citycare_credentials["email"],
            "password": "WrongPassword!",
        },
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for payload in scenarios:
            response = await client.post("/v1/auth/token", json=payload)
            assert response.status_code == 401
            data = response.json()
            assert data["error"]["message"] == "Invalid tenant, email, or password."


@pytest.mark.asyncio
async def test_validation_error_scrubs_raw_sensitive_inputs() -> None:
    """Validation errors must never echo raw submitted passwords, tokens, or sensitive inputs."""
    distinctive_secret_password = "SUPER_SECRET_PLAINTEXT_PASSWORD_VALUE_12345" * 3
    custom_req_id = "test-val-req-" + uuid.uuid4().hex
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            headers={"X-Request-ID": custom_req_id},
            json={
                "tenant": "SomeTenant",
                "email": "admin@example.com",
                "password": distinctive_secret_password,
            },
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"
        assert data["error"]["request_id"] == custom_req_id
        assert response.headers["X-Request-ID"] == custom_req_id
        # Crucial security check: sensitive input MUST NOT be present in body or text
        assert distinctive_secret_password not in response.text
        assert "SUPER_SECRET" not in str(data)


@pytest.mark.asyncio
async def test_validation_error_malformed_sensitive_input_not_echoed() -> None:
    """Malformed non-string sensitive values are not echoed in validation responses."""
    sensitive_dict = {"secret_key": "raw_sensitive_token_content_here"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/token",
            json={
                "tenant": "SomeTenant",
                "email": "not-an-email",
                "password": sensitive_dict,
            },
        )
        assert response.status_code == 422
        assert "raw_sensitive_token_content_here" not in response.text
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"
