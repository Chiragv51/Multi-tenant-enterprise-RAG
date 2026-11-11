"""tests/test_security.py — Unit tests for JWT security utilities and config validation.

Follows TDD. Verifies:
1. Config validation: JWT_SECRET_KEY must be >= 32 bytes (256 bits for HS256).
2. Token generation and claims integrity (user_id, tenant_id, role, groups, iat, exp).
3. Cryptographic and structural verification failures:
   - Wrong secret
   - Tampered payload / signature
   - Expired token
   - 'alg: none' algorithm attack
   - Missing / empty / malformed tenant_id (must be valid UUID)
   - Missing / empty user_id
   - Missing / invalid role (strictly tenant_admin, employee, platform_admin)
   - Missing exp claim
   - Non-list or non-string groups
4. Strict secrecy rule: Raw token string must NEVER leak in any AuthError exception message.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.security import (
    VALID_ROLES,
    AuthError,
    create_access_token,
    extract_tenant_id_from_api_key,
    generate_api_key,
    hash_api_key,
    verify_access_token,
)

VALID_SECRET = "super_secret_test_key_with_at_least_32_bytes_len!!"
WRONG_SECRET = "another_completely_different_key_with_32_bytes!!"


# ==============================================================================
# 1. Config Validation Tests
# ==============================================================================


def test_jwt_secret_key_minimum_length_enforcement() -> None:
    """Settings must fail to instantiate if JWT_SECRET_KEY is shorter than 32 bytes."""
    short_secret = "too-short-key-16b"
    with pytest.raises(ValidationError) as exc_info:
        Settings(JWT_SECRET_KEY=short_secret)

    errors = exc_info.value.errors()
    assert any("JWT_SECRET_KEY" in str(err) for err in errors)
    assert any("at least 32 bytes" in str(err) for err in errors)


def test_jwt_secret_key_empty_fails() -> None:
    """Settings must fail to instantiate if JWT_SECRET_KEY is empty."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(JWT_SECRET_KEY="")

    errors = exc_info.value.errors()
    assert any("JWT_SECRET_KEY" in str(err) for err in errors)


def test_jwt_secret_key_valid_length() -> None:
    """Settings instantiate successfully when JWT_SECRET_KEY >= 32 bytes."""
    settings = Settings(
        JWT_SECRET_KEY=VALID_SECRET,
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30,
    )
    assert settings.JWT_SECRET_KEY == VALID_SECRET
    assert settings.JWT_ALGORITHM == "HS256"
    assert settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES == 30


# ==============================================================================
# 2. Token Creation & Valid Verification Tests
# ==============================================================================


def test_create_and_verify_valid_access_token() -> None:
    """Verify that a valid token encodes all required claims and decodes cleanly."""
    user_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    role = "employee"
    groups = ["claims_reviewers", "support"]

    token = create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        groups=groups,
    )
    assert isinstance(token, str)
    assert len(token) > 20

    claims = verify_access_token(token)
    assert claims["user_id"] == user_id
    assert claims["tenant_id"] == tenant_id
    assert claims["role"] == role
    assert claims["groups"] == groups
    assert "iat" in claims
    assert "exp" in claims
    assert claims["exp"] > claims["iat"]


def test_create_token_with_uuid_objects() -> None:
    """create_access_token should accept uuid.UUID instances and convert them to strings."""
    user_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    token = create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role="tenant_admin",
        groups=["admins"],
    )
    claims = verify_access_token(token)
    assert claims["user_id"] == str(user_id)
    assert claims["tenant_id"] == str(tenant_id)
    assert claims["role"] == "tenant_admin"


def test_create_token_all_valid_roles() -> None:
    """Verify that all roles in VALID_ROLES create valid tokens."""
    for role in VALID_ROLES:
        token = create_access_token(
            user_id=str(uuid.uuid4()),
            tenant_id=str(uuid.uuid4()),
            role=role,
            groups=[],
        )
        claims = verify_access_token(token)
        assert claims["role"] == role


# ==============================================================================
# 3. Cryptographic and Tampering Failure Tests
# ==============================================================================


def test_verify_token_wrong_secret() -> None:
    """Token signed with an unauthorized secret must fail verification."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": ["all"],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    unauthorized_token = jwt.encode(payload, WRONG_SECRET, algorithm="HS256")

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(unauthorized_token)

    assert (
        "signature" in str(exc_info.value).lower()
        or "invalid" in str(exc_info.value).lower()
    )
    # Leak prevention
    assert unauthorized_token not in str(exc_info.value)


def test_verify_token_tampered() -> None:
    """Token whose payload or signature has been modified must be rejected."""
    token = create_access_token(
        user_id=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        role="employee",
        groups=[],
    )
    # Tamper with the signature portion
    parts = token.split(".")
    tampered_sig = parts[2][:-4] + "ABCD"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(tampered_token)

    assert tampered_token not in str(exc_info.value)


def test_verify_token_expired() -> None:
    """Token whose expiration time is in the past must be rejected."""
    token = create_access_token(
        user_id=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        role="employee",
        groups=[],
        expires_delta=timedelta(seconds=-10),  # Expired 10s ago
    )

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "expired" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_alg_none_attack() -> None:
    """Tokens using the 'none' algorithm must be rejected immediately."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "platform_admin",
        "groups": ["root"],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    none_token = jwt.encode(payload, key="", algorithm="none")

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(none_token)

    assert none_token not in str(exc_info.value)


# ==============================================================================
# 4. Mandatory Claims & Payload Validation Tests
# ==============================================================================


def _encode_custom_payload(payload: dict) -> str:
    """Helper to craft custom raw JWT payloads using valid secret."""
    from app.core.config import get_settings

    settings = get_settings()
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


def test_verify_token_missing_tenant_id() -> None:
    """Token missing tenant_id claim must be rejected."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    token = _encode_custom_payload(payload)

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "tenant_id" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_empty_tenant_id() -> None:
    """Token with empty tenant_id must be rejected."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": "",
        "role": "employee",
        "groups": [],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    token = _encode_custom_payload(payload)

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "tenant_id" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_invalid_tenant_id_uuid_format() -> None:
    """Token with non-UUID tenant_id format must be rejected."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": "invalid-tenant-id-not-a-uuid",
        "role": "employee",
        "groups": [],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    token = _encode_custom_payload(payload)

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert (
        "uuid" in str(exc_info.value).lower()
        or "tenant_id" in str(exc_info.value).lower()
    )
    assert token not in str(exc_info.value)


def test_verify_token_missing_user_id() -> None:
    """Token missing user_id must be rejected."""
    payload = {
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    token = _encode_custom_payload(payload)

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "user_id" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_empty_user_id() -> None:
    """Token with empty user_id must be rejected."""
    payload = {
        "user_id": "   ",
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    token = _encode_custom_payload(payload)

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "user_id" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_missing_role() -> None:
    """Token missing role claim must be rejected."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "groups": [],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    token = _encode_custom_payload(payload)

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "role" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_invalid_role() -> None:
    """Token with an unauthorized role (e.g. superuser, guest) must be rejected."""
    invalid_roles = ["superadmin", "guest", "admin", "root", ""]
    for role in invalid_roles:
        payload = {
            "user_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "role": role,
            "groups": [],
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        }
        token = _encode_custom_payload(payload)

        with pytest.raises(AuthError) as exc_info:
            verify_access_token(token)

        assert "role" in str(exc_info.value).lower()
        assert token not in str(exc_info.value)


def test_verify_token_missing_exp() -> None:
    """Token without exp claim must be rejected."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": datetime.now(UTC),
    }
    token = _encode_custom_payload(payload)

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert (
        "exp" in str(exc_info.value).lower()
        or "expiration" in str(exc_info.value).lower()
    )
    assert token not in str(exc_info.value)


def test_verify_token_invalid_groups_structure() -> None:
    """Token with groups not being a list of strings must be rejected."""
    invalid_groups_samples = [
        "not-a-list",
        [123, 456],
        {"a": "b"},
        None,
    ]
    for invalid_groups in invalid_groups_samples:
        payload = {
            "user_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "role": "employee",
            "groups": invalid_groups,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        }
        token = _encode_custom_payload(payload)

        with pytest.raises(AuthError) as exc_info:
            verify_access_token(token)

        assert "groups" in str(exc_info.value).lower()
        assert token not in str(exc_info.value)


# ==============================================================================
# 5. API Key Security & Cryptographic Unit Tests (Ticket T3c)
# ==============================================================================


def test_generate_api_key_format_and_entropy() -> None:
    """generate_api_key must generate unique keys with prefix, tenant ID, and 256 bits entropy."""
    tenant_id = uuid.uuid4()
    raw_key, key_hash = generate_api_key(tenant_id)

    assert raw_key.startswith("rag_key_")
    assert str(tenant_id) in raw_key
    assert len(key_hash) == 64
    assert all(c in "0123456789abcdef" for c in key_hash)

    # Key uniqueness
    raw_key_2, key_hash_2 = generate_api_key(tenant_id)
    assert raw_key != raw_key_2
    assert key_hash != key_hash_2


def test_extract_tenant_id_from_api_key_valid() -> None:
    """extract_tenant_id_from_api_key must extract valid UUID from standard formatted key."""
    tenant_id = uuid.uuid4()
    raw_key, _ = generate_api_key(tenant_id)

    extracted = extract_tenant_id_from_api_key(raw_key)
    assert extracted == tenant_id


def test_extract_tenant_id_from_api_key_invalid_cases() -> None:
    """extract_tenant_id_from_api_key must return None for malformed or tampered keys."""
    valid_uuid = uuid.uuid4()
    invalid_samples = [
        "",
        "not_a_key",
        "Bearer some_token",
        f"other_key_{valid_uuid}_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "rag_key_not-a-uuid_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        f"rag_key_{valid_uuid}_short",
        f"rag_key_{valid_uuid}",
        f"rag_key_{valid_uuid}_secret_extra_part",
    ]
    for sample in invalid_samples:
        assert extract_tenant_id_from_api_key(sample) is None


def test_hash_api_key_deterministic_and_safe() -> None:
    """hash_api_key must produce deterministic SHA-256 hex digest."""
    key = "rag_key_12345678-1234-5678-1234-567812345678_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    h1 = hash_api_key(key)
    h2 = hash_api_key(key)
    assert h1 == h2
    assert len(h1) == 64

    with pytest.raises(ValueError):
        hash_api_key("")
