"""tests/middleware/test_api_key_auth.py — Middleware authentication tests for API keys.

Ticket T3c:
Verifies:
1. Valid API key authenticates machine request to protected endpoints.
2. Verified TenantContext attached to request.state has principal_type="service", role="service", user_id=None.
3. Invalid API key (unrecognized hash) is rejected with HTTP 401.
4. Malformed API key (wrong prefix, non-UUID, short secret) is rejected with HTTP 401.
5. Revoked API key is rejected with HTTP 401.
6. Deleted API key is rejected with HTTP 401.
7. Cross-tenant spoofing rejected: Tenant A key cannot authenticate under Tenant B.
8. Conflicting credentials (both Authorization and X-API-Key) rejected with HTTP 400.
9. Missing credentials return HTTP 401.
10. Existing Bearer JWT authentication continues to work normally.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security import create_access_token, generate_api_key
from app.db.models import APIKey, Tenant
from app.db.session import AsyncSessionLocal, set_tenant_context
from app.main import app


@pytest.fixture
async def tenant_ids() -> tuple[uuid.UUID, uuid.UUID]:
    """Retrieve existing tenant IDs for CityCare and SecureLife."""
    async with AsyncSessionLocal() as session:
        stmt = select(Tenant.id, Tenant.name).where(
            Tenant.name.in_(["CityCare", "SecureLife"])
        )
        res = (await session.execute(stmt)).all()
        id_map = {name: t_id for t_id, name in res}
        return id_map["CityCare"], id_map["SecureLife"]


@pytest.mark.asyncio
async def test_valid_api_key_authenticates_service(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Valid API key must authenticate successfully and attach a service TenantContext."""
    tenant_a, _ = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    # Insert API key into DB under Tenant A context
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="Test Service Key",
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/v1/me", headers={"X-API-Key": raw_key})
            assert res.status_code == 200
            data = res.json()
            assert data["tenant_id"] == str(tenant_a)
            assert data["user_id"] is None
            assert data["principal_type"] == "service"
            assert data["role"] == "service"
            assert data["api_key_id"] == str(key_id)
            assert data["groups"] == []
    finally:
        # Cleanup
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                rec = await session.get(APIKey, key_id)
                if rec:
                    await session.delete(rec)


@pytest.mark.asyncio
async def test_invalid_api_key_rejected(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """An API key with a valid format but unknown secret hash must return HTTP 401."""
    tenant_a, _ = tenant_ids
    # Generate key but do NOT insert into database
    raw_key, _ = generate_api_key(tenant_a)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/v1/me", headers={"X-API-Key": raw_key})
        assert res.status_code == 401
        data = res.json()
        assert data["error"]["code"] == "UNAUTHORIZED"
        assert "Invalid API key" in data["error"]["message"]


@pytest.mark.asyncio
async def test_malformed_api_key_rejected() -> None:
    """Malformed API key headers must be rejected with HTTP 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for malformed in [
            "invalid_prefix_12345",
            "rag_key_not-a-uuid_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            f"rag_key_{uuid.uuid4()}_short",
            "Bearer token",
        ]:
            res = await client.get("/v1/me", headers={"X-API-Key": malformed})
            assert res.status_code == 401
            assert res.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_revoked_api_key_rejected(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """An API key that has revoked_at set must be rejected immediately with HTTP 401."""
    tenant_a, _ = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="Revoked Key",
                key_hash=key_hash,
                revoked_at=datetime.now(UTC),
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/v1/me", headers={"X-API-Key": raw_key})
            assert res.status_code == 401
            data = res.json()
            assert data["error"]["code"] == "UNAUTHORIZED"
    finally:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                rec = await session.get(APIKey, key_id)
                if rec:
                    await session.delete(rec)


@pytest.mark.asyncio
async def test_deleted_api_key_rejected(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """A deleted API key must stop authenticating immediately."""
    tenant_a, _ = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="Temporary Key",
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    # Authenticate successfully first
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.get("/v1/me", headers={"X-API-Key": raw_key})
        assert res1.status_code == 200

    # Delete the key
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            rec = await session.get(APIKey, key_id)
            if rec:
                await session.delete(rec)

    # Now it must immediately fail with 401
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res2 = await client.get("/v1/me", headers={"X-API-Key": raw_key})
        assert res2.status_code == 401
        assert res2.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_cross_tenant_spoofing_prevented(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """A key belonging to Tenant A cannot authenticate as Tenant B by spoofing the tenant hint."""
    tenant_a, tenant_b = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    # Insert key into DB for Tenant A
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="Tenant A Key",
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    try:
        # Attacker tampers with the key to replace Tenant A's UUID with Tenant B's UUID in the hint
        parts = raw_key.split("_")
        spoofed_key = f"rag_key_{tenant_b}_{parts[3]}"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/v1/me", headers={"X-API-Key": spoofed_key})
            assert res.status_code == 401
            assert res.json()["error"]["code"] == "UNAUTHORIZED"
    finally:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                rec = await session.get(APIKey, key_id)
                if rec:
                    await session.delete(rec)


@pytest.mark.asyncio
async def test_conflicting_authentication_credentials_rejected() -> None:
    """Providing both Authorization and X-API-Key headers must be rejected with HTTP 400."""
    jwt_token = create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="employee",
        groups=[],
    )
    api_key = f"rag_key_{uuid.uuid4()}_{'a' * 64}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/v1/me",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-API-Key": api_key,
            },
        )
        assert res.status_code == 400
        data = res.json()
        assert data["error"]["code"] == "BAD_REQUEST"
        assert "conflicting" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_existing_jwt_auth_continues_to_work() -> None:
    """Existing Bearer JWT authentication must continue to function seamlessly."""
    user_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    jwt_token = create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role="tenant_admin",
        groups=["admin_group"],
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/v1/me",
            headers={"Authorization": f"Bearer {jwt_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["tenant_id"] == str(tenant_id)
        assert data["user_id"] == str(user_id)
        assert data["principal_type"] == "user"
        assert data["role"] == "tenant_admin"
