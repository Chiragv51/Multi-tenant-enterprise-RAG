"""tests/api/test_api_keys.py — API key management endpoint tests.

Ticket T3c:
Verifies:
1. Tenant admin can create an API key; plaintext key is returned ONLY upon creation.
2. Database stores only the SHA-256 hash (never plaintext).
3. Tenant admin can list API keys; list does NOT expose plaintext keys or hashes.
4. Tenant admin can revoke an API key.
5. Tenant admin can delete an API key.
6. RBAC enforcement:
   - Employee cannot manage API keys (HTTP 403).
   - Machine API key cannot manage API keys (HTTP 403).
   - Unauthenticated request returns HTTP 401.
7. Cross-tenant isolation:
   - Tenant A admin cannot view Tenant B keys.
   - Tenant A admin cannot revoke Tenant B key (HTTP 404).
   - Tenant A admin cannot delete Tenant B key (HTTP 404).
"""

from __future__ import annotations

import hashlib
import uuid

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


@pytest.fixture
def admin_token_tenant_a(tenant_ids: tuple[uuid.UUID, uuid.UUID]) -> str:
    """JWT token for Tenant A tenant_admin."""
    tenant_a, _ = tenant_ids
    return create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=tenant_a,
        role="tenant_admin",
        groups=["Admins"],
    )


@pytest.fixture
def employee_token_tenant_a(tenant_ids: tuple[uuid.UUID, uuid.UUID]) -> str:
    """JWT token for Tenant A employee."""
    tenant_a, _ = tenant_ids
    return create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=tenant_a,
        role="employee",
        groups=["Staff"],
    )


@pytest.fixture
def admin_token_tenant_b(tenant_ids: tuple[uuid.UUID, uuid.UUID]) -> str:
    """JWT token for Tenant B tenant_admin."""
    _, tenant_b = tenant_ids
    return create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=tenant_b,
        role="tenant_admin",
        groups=["Admins"],
    )


@pytest.fixture
def platform_admin_token(tenant_ids: tuple[uuid.UUID, uuid.UUID]) -> str:
    """JWT token for platform_admin attempting tenant operations."""
    tenant_a, _ = tenant_ids
    return create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=tenant_a,
        role="platform_admin",
        groups=["Superusers"],
    )


@pytest.mark.asyncio
async def test_create_api_key_stores_hash_and_returns_plaintext_once(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
    admin_token_tenant_a: str,
) -> None:
    """Creating an API key must return the plaintext key once, and store only the SHA-256 hash in DB."""
    tenant_a, _ = tenant_ids
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/v1/api-keys",
            headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
            json={"name": "Ingestion Agent Key"},
        )
        assert res.status_code == 201
        data = res.json()
        assert "api_key" in data
        assert "id" in data
        assert data["name"] == "Ingestion Agent Key"
        plaintext_key = data["api_key"]
        created_id = uuid.UUID(data["id"])

    try:
        # Verify in database: key_hash must match sha256(plaintext_key) and NOT plaintext
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                db_record = await session.get(APIKey, created_id)
                assert db_record is not None
                assert (
                    db_record.key_hash
                    == hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()
                )
                assert plaintext_key not in db_record.key_hash
    finally:
        # Cleanup
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                rec = await session.get(APIKey, created_id)
                if rec:
                    await session.delete(rec)


@pytest.mark.asyncio
async def test_create_api_key_whitespace_name_rejected(
    admin_token_tenant_a: str,
) -> None:
    """Creating an API key with empty or whitespace-only name must return HTTP 422."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for bad_name in ["   ", "\t", "\n", ""]:
            res = await client.post(
                "/v1/api-keys",
                headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
                json={"name": bad_name},
            )
            assert res.status_code == 422
            data = res.json()
            assert data["error"]["code"] == "VALIDATION_ERROR"
            assert "name" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_list_api_keys_does_not_expose_hash_or_plaintext(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
    admin_token_tenant_a: str,
) -> None:
    """Listing API keys must return metadata without revealing key_hash or raw keys."""
    tenant_a, _ = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="Audit Bot",
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get(
                "/v1/api-keys",
                headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
            )
            assert res.status_code == 200
            items = res.json()
            assert isinstance(items, list)
            target_item = next(
                (item for item in items if item["id"] == str(key_id)), None
            )
            assert target_item is not None
            assert target_item["name"] == "Audit Bot"
            assert target_item["is_active"] is True
            assert target_item["revoked_at"] is None

            # Verify no secret leakage
            item_str = str(target_item).lower()
            assert "key_hash" not in item_str
            assert key_hash not in item_str
            assert raw_key not in item_str
    finally:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                rec = await session.get(APIKey, key_id)
                if rec:
                    await session.delete(rec)


@pytest.mark.asyncio
async def test_revoke_api_key(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
    admin_token_tenant_a: str,
) -> None:
    """Tenant admin can revoke an API key, immediately setting revoked_at."""
    tenant_a, _ = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="To Revoke",
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.post(
                f"/v1/api-keys/{key_id}/revoke",
                headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["revoked"] is True
            assert data["revoked_at"] is not None

        # Verify key can no longer authenticate
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            auth_res = await client.get("/v1/me", headers={"X-API-Key": raw_key})
            assert auth_res.status_code == 401
    finally:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                rec = await session.get(APIKey, key_id)
                if rec:
                    await session.delete(rec)


@pytest.mark.asyncio
async def test_delete_api_key(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
    admin_token_tenant_a: str,
) -> None:
    """Tenant admin can delete an API key permanently."""
    tenant_a, _ = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="To Delete",
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.delete(
            f"/v1/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
        )
        assert res.status_code == 204

    # Verify deleted from DB
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            assert await session.get(APIKey, key_id) is None


@pytest.mark.asyncio
async def test_api_key_management_rbac_permissions(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
    admin_token_tenant_a: str,
    employee_token_tenant_a: str,
    platform_admin_token: str,
) -> None:
    """Employees, platform admins, and service API keys must be forbidden from managing API keys (HTTP 403)."""
    tenant_a, _ = tenant_ids
    raw_key, key_hash = generate_api_key(tenant_a)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_a)
            api_key = APIKey(
                tenant_id=tenant_a,
                name="Service Key",
                key_hash=key_hash,
            )
            session.add(api_key)
            await session.flush()
            key_id = api_key.id

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Tenant admin is allowed
            res_admin = await client.get(
                "/v1/api-keys",
                headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
            )
            assert res_admin.status_code == 200

            # 2. Employee cannot create key (HTTP 403)
            res1 = await client.post(
                "/v1/api-keys",
                headers={"Authorization": f"Bearer {employee_token_tenant_a}"},
                json={"name": "Hacker Key"},
            )
            assert res1.status_code == 403

            # 3. Platform admin cannot manage tenant API keys (HTTP 403)
            res_plat = await client.post(
                "/v1/api-keys",
                headers={"Authorization": f"Bearer {platform_admin_token}"},
                json={"name": "Platform Key"},
            )
            assert res_plat.status_code == 403

            # 4. Machine API Key cannot manage API keys (HTTP 403)
            res2 = await client.post(
                "/v1/api-keys",
                headers={"X-API-Key": raw_key},
                json={"name": "Sub-Key"},
            )
            assert res2.status_code == 403

            # 5. Machine API Key cannot list API keys (HTTP 403)
            res3 = await client.get(
                "/v1/api-keys",
                headers={"X-API-Key": raw_key},
            )
            assert res3.status_code == 403

            # 6. Unauthenticated request returns HTTP 401
            res_unauth = await client.get("/v1/api-keys")
            assert res_unauth.status_code == 401
    finally:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_a)
                rec = await session.get(APIKey, key_id)
                if rec:
                    await session.delete(rec)


@pytest.mark.asyncio
async def test_cross_tenant_api_key_management_isolation(
    tenant_ids: tuple[uuid.UUID, uuid.UUID],
    admin_token_tenant_a: str,
    admin_token_tenant_b: str,
) -> None:
    """Tenant A admin cannot view, revoke, or delete Tenant B's API keys."""
    _, tenant_b = tenant_ids
    raw_key_b, key_hash_b = generate_api_key(tenant_b)

    # Create a key under Tenant B
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_b)
            api_key_b = APIKey(
                tenant_id=tenant_b,
                name="Tenant B Secret Key",
                key_hash=key_hash_b,
            )
            session.add(api_key_b)
            await session.flush()
            key_id_b = api_key_b.id

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Tenant A admin lists keys — must NOT contain Tenant B's key
            res_list = await client.get(
                "/v1/api-keys",
                headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
            )
            assert res_list.status_code == 200
            listed_ids = [item["id"] for item in res_list.json()]
            assert str(key_id_b) not in listed_ids

            # 2. Tenant A admin attempts to revoke Tenant B's key — must return 404
            res_revoke = await client.post(
                f"/v1/api-keys/{key_id_b}/revoke",
                headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
            )
            assert res_revoke.status_code == 404

            # 3. Tenant A admin attempts to delete Tenant B's key — must return 404
            res_delete = await client.delete(
                f"/v1/api-keys/{key_id_b}",
                headers={"Authorization": f"Bearer {admin_token_tenant_a}"},
            )
            assert res_delete.status_code == 404

        # Confirm Tenant B's key is STILL active and untouched
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_b)
                verified_key = await session.get(APIKey, key_id_b)
                assert verified_key is not None
                assert verified_key.revoked_at is None
    finally:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await set_tenant_context(session, tenant_b)
                rec = await session.get(APIKey, key_id_b)
                if rec:
                    await session.delete(rec)
