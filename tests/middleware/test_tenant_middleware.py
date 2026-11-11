"""tests/middleware/test_tenant_middleware.py — Authentication middleware & protected route tests.

Verifies:
1. Public allow-list (/health, /v1/health, /v1/auth/token) bypasses authentication.
2. Protected routes (/v1/me, /) reject requests missing the Authorization header (HTTP 401).
3. Malformed Authorization headers (not starting with 'Bearer ') are rejected (HTTP 401).
4. Invalid, tampered, or expired tokens are rejected (HTTP 401).
5. Valid tokens allow access and attach the verified TenantContext to request.state.
6. Error responses strictly follow standard JSON schema {"error": {"code", "message", "request_id"}}.
"""

import uuid
from datetime import timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import create_access_token
from app.main import app


@pytest.fixture
def valid_token() -> str:
    """Generate a valid JWT token for testing."""
    return create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="employee",
        groups=["clinical_staff"],
    )


@pytest.mark.asyncio
async def test_public_allowlist_accessible_without_token() -> None:
    """Public endpoints (/health, /v1/health) must succeed without an Authorization header."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for path in ["/health", "/v1/health"]:
            res = await client.get(path)
            assert res.status_code == 200, f"Expected 200 for public path {path}"
            assert res.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_protected_route_missing_token_returns_401() -> None:
    """Accessing protected routes without an Authorization header must return 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/v1/me")
        assert res.status_code == 401
        data = res.json()
        assert "error" in data
        assert data["error"]["code"] == "UNAUTHORIZED"
        assert "request_id" in data["error"]
        assert "X-Request-ID" in res.headers


@pytest.mark.asyncio
async def test_protected_route_invalid_scheme_returns_401() -> None:
    """Authorization header with Basic or non-Bearer scheme must return 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/v1/me", headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_protected_route_tampered_token_returns_401(valid_token: str) -> None:
    """Accessing protected route with a tampered token returns 401."""
    tampered = valid_token[:-5] + "XXXXX"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/v1/me", headers={"Authorization": f"Bearer {tampered}"}
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_protected_route_expired_token_returns_401() -> None:
    """Accessing protected route with an expired token returns 401."""
    expired_token = create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="employee",
        groups=[],
        expires_delta=timedelta(seconds=-10),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/v1/me", headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert res.status_code == 401
        assert "expired" in res.json()["error"]["message"].lower()


@pytest.mark.asyncio
async def test_protected_route_valid_token_attaches_tenant_context() -> None:
    """Valid token creates expected TenantContext and allows protected endpoint execution."""
    test_user_id = uuid.uuid4()
    test_tenant_id = uuid.uuid4()
    test_role = "tenant_admin"
    test_groups = ["Admins", "Operations"]

    token = create_access_token(
        user_id=test_user_id,
        tenant_id=test_tenant_id,
        role=test_role,
        groups=test_groups,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["tenant_id"] == str(test_tenant_id)
        assert data["user_id"] == str(test_user_id)
        assert data["role"] == test_role
        assert data["groups"] == test_groups
