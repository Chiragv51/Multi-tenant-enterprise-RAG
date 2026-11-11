"""tests/middleware/test_tenant_middleware.py — Authentication middleware, protected routes & request-ID tests.

Ticket T3 Hardening:
1. Public allow-list (/health, /v1/health, /v1/auth/token) bypasses authentication.
2. Protected routes (/v1/me, /) reject requests missing authentication (HTTP 401).
3. Malformed Authorization headers (not starting with 'Bearer ') are rejected (HTTP 401).
4. Invalid, tampered, or expired tokens are rejected (HTTP 401).
5. Valid tokens allow access and attach verified TenantContext to request.state.
6. Error responses strictly follow standard JSON schema {"error": {"code", "message", "request_id"}}.
7. Request ID consistency:
   - Preserves incoming X-Request-ID on all errors.
   - Generates consistent request ID across header and JSON payload when none supplied.
   - Preserves X-Request-ID across JWT and API key auth failures.
8. Client-controlled tenant ID cannot override verified context.
"""

from __future__ import annotations

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
        assert res.headers["X-Request-ID"] == data["error"]["request_id"]


@pytest.mark.asyncio
async def test_protected_route_missing_auth_with_supplied_request_id() -> None:
    """Incoming X-Request-ID must be preserved in both response header and error JSON envelope."""
    custom_req_id = "test-req-id-" + uuid.uuid4().hex
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/v1/me", headers={"X-Request-ID": custom_req_id})
        assert res.status_code == 401
        data = res.json()
        assert data["error"]["request_id"] == custom_req_id
        assert res.headers["X-Request-ID"] == custom_req_id


@pytest.mark.asyncio
async def test_protected_route_invalid_jwt_with_supplied_request_id() -> None:
    """Invalid JWT failure must preserve incoming X-Request-ID in both header and JSON envelope."""
    custom_req_id = "custom-jwt-err-" + uuid.uuid4().hex
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/v1/me",
            headers={
                "Authorization": "Bearer invalid.tampered.token",
                "X-Request-ID": custom_req_id,
            },
        )
        assert res.status_code == 401
        data = res.json()
        assert data["error"]["request_id"] == custom_req_id
        assert res.headers["X-Request-ID"] == custom_req_id


@pytest.mark.asyncio
async def test_protected_route_api_key_failure_with_supplied_request_id() -> None:
    """API key failure must preserve incoming X-Request-ID in both header and JSON envelope."""
    custom_req_id = "custom-apikey-err-" + uuid.uuid4().hex
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/v1/me",
            headers={
                "X-API-Key": "rag_key_malformed",
                "X-Request-ID": custom_req_id,
            },
        )
        assert res.status_code == 401
        data = res.json()
        assert data["error"]["request_id"] == custom_req_id
        assert res.headers["X-Request-ID"] == custom_req_id


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


@pytest.mark.asyncio
async def test_client_supplied_tenant_id_in_query_ignored() -> None:
    """Client cannot override verified tenant context via query parameter or spoofing."""
    verified_tenant = uuid.uuid4()
    spoofed_tenant = uuid.uuid4()
    user_id = uuid.uuid4()

    token = create_access_token(
        user_id=user_id,
        tenant_id=verified_tenant,
        role="employee",
        groups=[],
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            f"/v1/me?tenant_id={spoofed_tenant}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["tenant_id"] == str(verified_tenant)
        assert data["tenant_id"] != str(spoofed_tenant)


@pytest.mark.asyncio
async def test_request_id_crlf_injection_rejected() -> None:
    """CRLF characters in X-Request-ID must be rejected and replaced with a valid UUID."""
    malicious_header = "valid-prefix\r\nInjected-Header: evil"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health", headers={"X-Request-ID": malicious_header})
        assert res.status_code == 200
        header_val = res.headers["X-Request-ID"]
        assert "\r" not in header_val
        assert "\n" not in header_val
        assert "Injected-Header" not in header_val
        # Must be valid UUID
        parsed_uuid = uuid.UUID(header_val)
        assert str(parsed_uuid) == header_val


@pytest.mark.asyncio
async def test_request_id_control_characters_rejected() -> None:
    """Control characters in X-Request-ID must be rejected and replaced with a valid UUID."""
    for bad_id in ["test\x00id", "test\x1b[31mid", "test\tid", "   ", ""]:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/health", headers={"X-Request-ID": bad_id})
            assert res.status_code == 200
            header_val = res.headers["X-Request-ID"]
            if bad_id.strip():
                assert bad_id not in header_val
            assert uuid.UUID(header_val)


@pytest.mark.asyncio
async def test_request_id_overlong_rejected() -> None:
    """Overlong X-Request-ID (>128 chars) must be replaced with a valid UUID."""
    overlong = "a" * 129
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health", headers={"X-Request-ID": overlong})
        assert res.status_code == 200
        header_val = res.headers["X-Request-ID"]
        assert header_val != overlong
        assert len(header_val) < 128
        assert uuid.UUID(header_val)


@pytest.mark.asyncio
async def test_invalid_request_id_on_auth_failure_uses_same_sanitized_uuid() -> None:
    """Invalid request ID on authentication failure returns sanitized UUID in header and JSON body."""
    bad_req_id = "bad\r\nrequest\x00id"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/v1/me", headers={"X-Request-ID": bad_req_id})
        assert res.status_code == 401
        header_val = res.headers["X-Request-ID"]
        data = res.json()
        assert data["error"]["request_id"] == header_val
        assert bad_req_id not in header_val
        assert uuid.UUID(header_val)
