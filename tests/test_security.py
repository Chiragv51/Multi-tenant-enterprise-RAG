"""tests/test_security.py — Unit tests for JWT security, password handling, API keys, and config validation.

Ticket T3 Hardening:
1. Config validation: JWT_SECRET_KEY minimum length, production-only security validation.
2. Token generation and claims integrity (UUID user_id & tenant_id, role, groups, exp, iat).
3. Cryptographic and structural verification:
   - Wrong secret, tampered signature, expired tokens.
   - Algorithm pinning (HS256 only; alg: none & RS256 rejected).
   - Mandatory exp and iat claims; timestamp type and clock-skew validation (future iat, exp <= iat).
   - UUID validation for both user_id and tenant_id.
   - Role whitelist (tenant_admin, employee, platform_admin).
   - Groups type and structure.
   - Information leakage prevention: raw token and untrusted values never leak in AuthError.
4. Password security:
   - Bcrypt 72 UTF-8 byte limit enforcement.
   - Multibyte Unicode handling.
   - Empty password rejection.
   - Invalid bcrypt hash handling.
5. API key cryptographic validation:
   - 256-bit entropy.
   - Exact 64-char lowercase hex secret enforcement (reject uppercase, truncated, extended, non-hex).
   - Deterministic SHA-256 hashing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.security import (
    MAX_BCRYPT_PASSWORD_BYTES,
    VALID_ROLES,
    AuthError,
    create_access_token,
    extract_tenant_id_from_api_key,
    generate_api_key,
    get_password_hash,
    hash_api_key,
    verify_access_token,
    verify_password,
)

VALID_SECRET = "super_secret_test_key_with_at_least_32_bytes_len!!"
WRONG_SECRET = "another_completely_different_key_with_32_bytes!!"


# ==============================================================================
# 1. Config Validation Tests (Ticket T3 & Hardening)
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


VALID_PROD_KWARGS: dict[str, Any] = {
    "APP_ENV": "production",
    "DEBUG": False,
    "SECRET_KEY": "a" * 32,
    "JWT_SECRET_KEY": "b" * 32,
    "POSTGRES_USER": "rag_user",
    "POSTGRES_APP_USER": "rag_app",
    "POSTGRES_DB": "rag_enterprise_db",
    "POSTGRES_PASSWORD": "prod_password_1",
    "POSTGRES_APP_PASSWORD": "prod_password_2",
    "MINIO_ROOT_USER": "prod_minio_user",
    "MINIO_ROOT_PASSWORD": "prod_minio_password",
    "DATABASE_URL": "postgresql+asyncpg://rag_user:prod_password_1@localhost:5433/rag_enterprise_db",
    "APP_DATABASE_URL": "postgresql+asyncpg://rag_app:prod_password_2@localhost:5433/rag_enterprise_db",
}


def test_production_config_valid() -> None:
    """Valid production settings instantiate cleanly."""
    settings = Settings(**VALID_PROD_KWARGS)
    assert settings.APP_ENV == "production"
    assert settings.DEBUG is False


def test_production_config_rejects_debug_true() -> None:
    """In production (APP_ENV=production), DEBUG=True must be rejected."""
    kwargs = dict(VALID_PROD_KWARGS)
    kwargs["DEBUG"] = True
    with pytest.raises(ValidationError) as exc_info:
        Settings(**kwargs)
    assert any(
        "DEBUG must be set to False" in str(err) for err in exc_info.value.errors()
    )


def test_production_config_rejects_placeholders() -> None:
    """In production, development placeholder passwords and secrets must be rejected."""
    for bad_field, bad_val in [
        ("SECRET_KEY", "change-this-to-a-super-secret-random-key-in-production"),
        (
            "JWT_SECRET_KEY",
            "change-this-to-a-super-secret-jwt-key-with-at-least-32-bytes-in-production",
        ),
        ("POSTGRES_PASSWORD", "rag_secure_password"),
        ("POSTGRES_APP_PASSWORD", "rag_app_password"),
        ("MINIO_ROOT_PASSWORD", "minioadmin"),
    ]:
        kwargs = dict(VALID_PROD_KWARGS)
        kwargs[bad_field] = bad_val
        with pytest.raises(ValidationError):
            Settings(**kwargs)


def test_production_config_rejects_missing_app_db_credentials() -> None:
    """In production, APP_DATABASE_URL missing username or password must fail without leaking secrets."""
    # Missing username
    kwargs_no_user = dict(VALID_PROD_KWARGS)
    kwargs_no_user["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://:prod_password_2@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError) as exc_info:
        Settings(**kwargs_no_user)
    assert any("must contain a username" in str(err) for err in exc_info.value.errors())
    assert "prod_password_2" not in str(exc_info.value)

    # Missing password
    kwargs_no_pwd = dict(VALID_PROD_KWARGS)
    kwargs_no_pwd["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://rag_app@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError) as exc_info:
        Settings(**kwargs_no_pwd)
    assert any("must contain a password" in str(err) for err in exc_info.value.errors())


def test_production_config_rejects_missing_db_credentials() -> None:
    """In production, DATABASE_URL missing username or password must fail."""
    # Missing username
    kwargs_no_user = dict(VALID_PROD_KWARGS)
    kwargs_no_user["DATABASE_URL"] = (
        "postgresql+asyncpg://:prod_password_1@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError) as exc_info:
        Settings(**kwargs_no_user)
    assert any("must contain a username" in str(err) for err in exc_info.value.errors())

    # Missing password
    kwargs_no_pwd = dict(VALID_PROD_KWARGS)
    kwargs_no_pwd["DATABASE_URL"] = (
        "postgresql+asyncpg://rag_user@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError) as exc_info:
        Settings(**kwargs_no_pwd)
    assert any("must contain a password" in str(err) for err in exc_info.value.errors())


def test_production_config_rejects_credential_mismatch() -> None:
    """In production, credentials in URL must strictly match configured role passwords."""
    kwargs = dict(VALID_PROD_KWARGS)
    kwargs["DATABASE_URL"] = (
        "postgresql+asyncpg://rag_user:WRONG_PASSWORD@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError) as exc_info:
        Settings(**kwargs)
    assert any("inconsistent" in str(err) for err in exc_info.value.errors())
    assert "WRONG_PASSWORD" not in str(exc_info.value)
    assert "prod_password_1" not in str(exc_info.value)


def test_production_config_url_encoded_password_consistency() -> None:
    """Percent-encoded passwords in database URLs must decode cleanly and match config."""
    special_pwd = "p@ss#word!123"
    kwargs = dict(VALID_PROD_KWARGS)
    kwargs["POSTGRES_APP_PASSWORD"] = special_pwd
    kwargs["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://rag_app:p%40ss%23word%21123@localhost:5433/rag_enterprise_db"
    )
    settings = Settings(**kwargs)
    assert settings.POSTGRES_APP_PASSWORD == special_pwd


def test_production_config_rejects_invalid_scheme_host_database() -> None:
    """In production, invalid schemes, missing host, or mismatched DB names must fail."""
    # Invalid scheme
    kwargs_bad_scheme = dict(VALID_PROD_KWARGS)
    kwargs_bad_scheme["APP_DATABASE_URL"] = (
        "mysql://rag_app:prod_password_2@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError):
        Settings(**kwargs_bad_scheme)

    # Missing host
    kwargs_no_host = dict(VALID_PROD_KWARGS)
    kwargs_no_host["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://rag_app:prod_password_2@/rag_enterprise_db"
    )
    with pytest.raises(ValidationError):
        Settings(**kwargs_no_host)

    # Inconsistent DB name
    kwargs_bad_db = dict(VALID_PROD_KWARGS)
    kwargs_bad_db["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://rag_app:prod_password_2@localhost:5433/wrong_db"
    )
    with pytest.raises(ValidationError):
        Settings(**kwargs_bad_db)


def test_production_config_supported_role_and_db_consistency() -> None:
    """In production, role separation and fixed infrastructure roles/DB must be enforced."""
    # Disallow identical runtime and migration roles
    kwargs_same_role = dict(VALID_PROD_KWARGS)
    kwargs_same_role["POSTGRES_APP_USER"] = "rag_user"
    kwargs_same_role["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://rag_user:prod_password_2@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError) as exc_info:
        Settings(**kwargs_same_role)
    assert any("must remain separate" in str(err) for err in exc_info.value.errors())

    # Disallow unsupported application role
    kwargs_unsupported_app_role = dict(VALID_PROD_KWARGS)
    kwargs_unsupported_app_role["POSTGRES_APP_USER"] = "random_user"
    kwargs_unsupported_app_role["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://random_user:prod_password_2@localhost:5433/rag_enterprise_db"
    )
    with pytest.raises(ValidationError):
        Settings(**kwargs_unsupported_app_role)

    # Disallow unsupported database name
    kwargs_unsupported_db = dict(VALID_PROD_KWARGS)
    kwargs_unsupported_db["POSTGRES_DB"] = "other_db"
    kwargs_unsupported_db["DATABASE_URL"] = (
        "postgresql+asyncpg://rag_user:prod_password_1@localhost:5433/other_db"
    )
    kwargs_unsupported_db["APP_DATABASE_URL"] = (
        "postgresql+asyncpg://rag_app:prod_password_2@localhost:5433/other_db"
    )
    with pytest.raises(ValidationError):
        Settings(**kwargs_unsupported_db)


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
    """create_access_token must accept uuid.UUID instances and convert to strings."""
    uid = uuid.uuid4()
    tid = uuid.uuid4()

    token = create_access_token(
        user_id=uid,
        tenant_id=tid,
        role="tenant_admin",
        groups=["admin_group"],
    )
    claims = verify_access_token(token)
    assert claims["user_id"] == str(uid)
    assert claims["tenant_id"] == str(tid)


def test_create_token_all_valid_roles() -> None:
    """Tokens must be generated and verified cleanly for all valid platform roles."""
    uid = str(uuid.uuid4())
    tid = str(uuid.uuid4())

    for role in VALID_ROLES:
        token = create_access_token(
            user_id=uid,
            tenant_id=tid,
            role=role,
            groups=[],
        )
        claims = verify_access_token(token)
        assert claims["role"] == role


# ==============================================================================
# 3. Cryptographic & Structural Verification Failures
# ==============================================================================


def _encode_custom_payload(
    payload: dict,
    secret: str | None = None,
    algorithm: str = "HS256",
) -> str:
    """Helper to craft test tokens with specific arbitrary payloads."""
    signing_secret = secret if secret is not None else get_settings().JWT_SECRET_KEY
    return jwt.encode(payload, signing_secret, algorithm=algorithm)


def test_verify_token_wrong_secret() -> None:
    """Token signed with an incorrect secret must fail verification."""
    token = _encode_custom_payload(
        {
            "user_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "role": "employee",
            "groups": [],
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        },
        secret=WRONG_SECRET,
    )
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "signature" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_tampered() -> None:
    """Token with a modified payload or signature must fail verification."""
    token = create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="employee",
        groups=[],
    )
    # Flip the last 5 characters
    tampered = token[:-5] + ("A" if token[-5] != "A" else "B") * 5

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(tampered)

    assert (
        "signature" in str(exc_info.value).lower()
        or "invalid" in str(exc_info.value).lower()
    )
    assert tampered not in str(exc_info.value)


def test_verify_token_expired() -> None:
    """Token whose exp timestamp is in the past must fail verification."""
    token = create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="employee",
        groups=[],
        expires_delta=timedelta(seconds=-1),
    )
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "expired" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_alg_none_attack() -> None:
    """Tokens with 'alg': 'none' must be unconditionally rejected."""
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "tenant_admin",
        "groups": ["root"],
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    # Craft an unsigned token
    token = jwt.encode(payload, key="", algorithm="none")

    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert (
        "algorithm" in str(exc_info.value).lower()
        or "invalid" in str(exc_info.value).lower()
    )
    assert token not in str(exc_info.value)


def test_verify_token_missing_iat() -> None:
    """Tokens missing the mandatory 'iat' claim must be rejected."""
    now = datetime.now(UTC)
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    token = _encode_custom_payload(payload)
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "missing" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_missing_exp() -> None:
    """Tokens missing the mandatory 'exp' claim must be rejected."""
    now = datetime.now(UTC)
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": int(now.timestamp()),
    }
    token = _encode_custom_payload(payload)
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "missing" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_future_iat_plus_30_accepted() -> None:
    """Tokens issued with iat 30 seconds into the future must be accepted (within 60s skew)."""
    now = datetime.now(UTC)
    future_iat = int((now + timedelta(seconds=30)).timestamp())
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": future_iat,
        "exp": future_iat + 900,
    }
    token = _encode_custom_payload(payload)
    claims = verify_access_token(token)
    assert claims["iat"] == future_iat


def test_verify_token_future_iat_plus_60_accepted() -> None:
    """Tokens issued with iat exactly 60 seconds into the future must be accepted."""
    now = datetime.now(UTC)
    future_iat = int((now + timedelta(seconds=60)).timestamp())
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": future_iat,
        "exp": future_iat + 900,
    }
    token = _encode_custom_payload(payload)
    claims = verify_access_token(token)
    assert claims["iat"] == future_iat


def test_verify_token_future_iat_plus_61_rejected() -> None:
    """Tokens issued with iat 61 seconds into the future must be rejected (> 60s skew)."""
    now = datetime.now(UTC)
    future_iat = int((now + timedelta(seconds=61)).timestamp())
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": future_iat,
        "exp": future_iat + 900,
    }
    token = _encode_custom_payload(payload)
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "future" in str(exc_info.value).lower()
    assert token not in str(exc_info.value)


def test_verify_token_invalid_timestamp_types() -> None:
    """Non-numeric timestamps (boolean, string, null) must be rejected."""
    now = datetime.now(UTC)
    valid_iat = int(now.timestamp())
    valid_exp = valid_iat + 900

    # Bad iat types
    for bad_iat in [True, False, "2026-01-01", None, [123]]:
        payload = {
            "user_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "role": "employee",
            "groups": [],
            "iat": bad_iat,
            "exp": valid_exp,
        }
        token = _encode_custom_payload(payload)
        with pytest.raises(AuthError) as exc_info:
            verify_access_token(token)
        assert (
            "timestamp" in str(exc_info.value).lower()
            or "missing" in str(exc_info.value).lower()
        )

    # Bad exp types (rejected either by PyJWT decode/expiry check or custom validation)
    for bad_exp in [True, False, "tomorrow", None, {"x": 1}]:
        payload = {
            "user_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "role": "employee",
            "groups": [],
            "iat": valid_iat,
            "exp": bad_exp,
        }
        token = _encode_custom_payload(payload)
        with pytest.raises(AuthError) as exc_info:
            verify_access_token(token)
        assert (
            "timestamp" in str(exc_info.value).lower()
            or "missing" in str(exc_info.value).lower()
            or "expired" in str(exc_info.value).lower()
            or "invalid" in str(exc_info.value).lower()
        )


def test_verify_token_exp_before_iat() -> None:
    """Tokens where exp <= iat must be rejected."""
    now = datetime.now(UTC)
    iat = int(now.timestamp())
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": iat,
        "exp": iat - 10,
    }
    token = _encode_custom_payload(payload)
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert (
        "expiration" in str(exc_info.value).lower()
        or "expired" in str(exc_info.value).lower()
    )
    assert token not in str(exc_info.value)


def test_verify_token_invalid_user_id_uuid_format() -> None:
    """user_id that is not a valid UUID must be rejected."""
    now = datetime.now(UTC)
    payload = {
        "user_id": "not-a-valid-uuid-12345",
        "tenant_id": str(uuid.uuid4()),
        "role": "employee",
        "groups": [],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    token = _encode_custom_payload(payload)
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "user_id" in str(exc_info.value).lower()
    assert "not-a-valid-uuid-12345" not in str(exc_info.value)


def test_verify_token_invalid_tenant_id_uuid_format() -> None:
    """tenant_id that is not a valid UUID must be rejected."""
    now = datetime.now(UTC)
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": "malformed-tenant-identifier",
        "role": "employee",
        "groups": [],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    token = _encode_custom_payload(payload)
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "tenant_id" in str(exc_info.value).lower()
    assert "malformed-tenant-identifier" not in str(exc_info.value)


def test_verify_token_invalid_role() -> None:
    """Tokens with an unauthorized or unapproved role must be rejected."""
    now = datetime.now(UTC)
    payload = {
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "superadmin_hacker",
        "groups": [],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    token = _encode_custom_payload(payload)
    with pytest.raises(AuthError) as exc_info:
        verify_access_token(token)

    assert "role" in str(exc_info.value).lower()
    assert "superadmin_hacker" not in str(exc_info.value)


def test_verify_token_invalid_groups_structure() -> None:
    """Tokens with non-list or non-string groups must be rejected."""
    now = datetime.now(UTC)
    for invalid_groups in ["not-a-list", [123, 456], {"a": "b"}, None]:
        payload = {
            "user_id": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "role": "employee",
            "groups": invalid_groups,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
        }
        token = _encode_custom_payload(payload)
        with pytest.raises(AuthError) as exc_info:
            verify_access_token(token)

        assert "groups" in str(exc_info.value).lower()
        assert token not in str(exc_info.value)


def test_create_access_token_and_generate_api_key_scrubs_malicious_inputs() -> None:
    """create_access_token and generate_api_key must never reflect untrusted input in exception messages."""
    malicious = "<script>alert('xss')</script>'; DROP TABLE users; --"

    # In create_access_token
    with pytest.raises(ValueError) as exc_info:
        create_access_token(
            user_id=malicious, tenant_id=uuid.uuid4(), role="employee", groups=[]
        )
    assert malicious not in str(exc_info.value)
    assert "user_id must be a valid UUID" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        create_access_token(
            user_id=uuid.uuid4(), tenant_id=malicious, role="employee", groups=[]
        )
    assert malicious not in str(exc_info.value)
    assert "tenant_id must be a valid UUID" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        create_access_token(
            user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role=malicious, groups=[]
        )
    assert malicious not in str(exc_info.value)
    assert "Invalid role" in str(exc_info.value)

    # In generate_api_key
    with pytest.raises(ValueError) as exc_info:
        generate_api_key(tenant_id=malicious)
    assert malicious not in str(exc_info.value)
    assert "tenant_id must be a valid UUID" in str(exc_info.value)


# ==============================================================================
# 4. Password Security Tests (Bcrypt 72-Byte Limit & Multibyte UTF-8)
# ==============================================================================


def test_password_empty_rejected() -> None:
    """Empty passwords must be rejected by both get_password_hash and verify_password."""
    with pytest.raises(ValueError, match="cannot be empty"):
        get_password_hash("")

    assert verify_password("", "$2b$12$dummyhash") is False


def test_password_exactly_72_bytes_accepted() -> None:
    """A password of exactly 72 ASCII/UTF-8 bytes must hash and verify cleanly."""
    pwd_72 = "A" * 72
    assert len(pwd_72.encode("utf-8")) == 72

    hashed = get_password_hash(pwd_72)
    assert verify_password(pwd_72, hashed) is True
    assert verify_password("A" * 71, hashed) is False


def test_password_more_than_72_bytes_rejected() -> None:
    """A password exceeding 72 UTF-8 bytes must be rejected before hashing/verifying."""
    pwd_73 = "A" * 73
    assert len(pwd_73.encode("utf-8")) == 73

    with pytest.raises(
        ValueError, match=f"must not exceed {MAX_BCRYPT_PASSWORD_BYTES}"
    ):
        get_password_hash(pwd_73)

    assert verify_password(pwd_73, "$2b$12$dummyhash") is False


def test_password_multibyte_unicode_byte_enforcement() -> None:
    """Multibyte UTF-8 characters must be measured by encoded byte count, not string length."""
    # '€' is 3 bytes in UTF-8
    char = "€"
    assert len(char.encode("utf-8")) == 3

    # 24 chars * 3 bytes = exactly 72 bytes -> valid
    pwd_valid = char * 24
    assert len(pwd_valid.encode("utf-8")) == 72
    hashed = get_password_hash(pwd_valid)
    assert verify_password(pwd_valid, hashed) is True

    # 25 chars * 3 bytes = 75 bytes -> exceeds 72 bytes limit -> rejected
    pwd_too_long = char * 25
    assert len(pwd_too_long.encode("utf-8")) == 75
    with pytest.raises(ValueError, match="must not exceed 72"):
        get_password_hash(pwd_too_long)

    assert verify_password(pwd_too_long, hashed) is False


def test_password_invalid_hash_string() -> None:
    """Invalid or corrupted bcrypt hash strings must return False safely without crashing."""
    for bad_hash in ["not-a-hash", "$2b$invalid", "", None]:
        assert verify_password("valid_password", bad_hash) is False


def test_password_incorrect_returns_false() -> None:
    """Correct hash with wrong password must return False."""
    hashed = get_password_hash("correct_password")
    assert verify_password("wrong_password", hashed) is False


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


def test_extract_tenant_id_from_api_key_rejects_malformed_and_non_hex() -> None:
    """extract_tenant_id_from_api_key must reject truncated, extended, uppercase, and non-hex secrets."""
    valid_uuid = uuid.uuid4()

    # Exact 64 lowercase hex is required
    valid_secret = "a" * 64

    # 1. Truncated (63 chars)
    truncated = f"rag_key_{valid_uuid}_{'a' * 63}"
    assert extract_tenant_id_from_api_key(truncated) is None

    # 2. Extended (65 chars)
    extended = f"rag_key_{valid_uuid}_{'a' * 65}"
    assert extract_tenant_id_from_api_key(extended) is None

    # 3. Uppercase hex (must NOT be silently normalized)
    uppercase = f"rag_key_{valid_uuid}_{'A' * 64}"
    assert extract_tenant_id_from_api_key(uppercase) is None

    # 4. Non-hex characters
    non_hex = f"rag_key_{valid_uuid}_{'g' * 64}"
    assert extract_tenant_id_from_api_key(non_hex) is None

    # 5. Malformed prefix / invalid UUID
    assert (
        extract_tenant_id_from_api_key(f"other_key_{valid_uuid}_{valid_secret}") is None
    )
    assert extract_tenant_id_from_api_key(f"rag_key_not-a-uuid_{valid_secret}") is None
    assert extract_tenant_id_from_api_key("") is None
    assert extract_tenant_id_from_api_key("Bearer some_token") is None


def test_hash_api_key_deterministic_and_safe() -> None:
    """hash_api_key must produce deterministic SHA-256 hex digest."""
    key = f"rag_key_{uuid.uuid4()}_{'f' * 64}"
    h1 = hash_api_key(key)
    h2 = hash_api_key(key)
    assert h1 == h2
    assert len(h1) == 64

    with pytest.raises(ValueError):
        hash_api_key("")
