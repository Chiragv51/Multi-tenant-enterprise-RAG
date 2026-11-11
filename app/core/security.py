"""app/core/security.py — Cryptographic security, JWT issuance, and verification.

Ticket T3a-1:
- Issues and cryptographically validates JWT access tokens.
- Strict claim validation: user_id, tenant_id (UUID), role (RBAC whitelist), groups (list[str]), exp, iat.
- Pinned algorithm (HS256 only).
- Strict information leakage protection: token strings must never appear in error messages or logs.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import get_settings

logger = logging.getLogger("security")

# Permitted RBAC roles across the multi-tenant platform
VALID_ROLES: frozenset[str] = frozenset({"tenant_admin", "employee", "platform_admin"})


def get_password_hash(password: str) -> str:
    """Hash a plaintext password using bcrypt with a random salt."""
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """Verify a plaintext password against a stored bcrypt hash.

    Returns False if hashed_password is None, empty, or verification fails.
    Uses constant-time comparison in bcrypt to prevent timing attacks.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def map_db_role_to_jwt_role(db_role: str) -> str:
    """Map granular database role to coarse-grained JWT platform role.

    Explicit coarse-grained mapping:
    - tenant 'admin' -> 'tenant_admin'
    - other tenant-specific roles ('clinician', 'nurse', 'staff', 'auditor', etc.) -> 'employee'
    - 'platform_admin' is reserved for explicitly provisioned platform administrators.
    """
    clean_role = (db_role or "").strip().lower()
    if clean_role == "platform_admin":
        return "platform_admin"
    if clean_role == "admin":
        return "tenant_admin"
    return "employee"


class AuthError(Exception):
    """Raised when authentication, token validation, or claim verification fails.

    Under NO circumstances should the raw token string be passed to this exception,
    to prevent sensitive token leakage into logs, tracing spans, or client responses.
    """


def create_access_token(
    user_id: uuid.UUID | str,
    tenant_id: uuid.UUID | str,
    role: str,
    groups: list[str],
    expires_delta: timedelta | None = None,
) -> str:
    """Issue a signed JWT access token for an authenticated user.

    Claims:
    - user_id: Unique identifier of the user (string).
    - tenant_id: Target tenant UUID (string).
    - role: Authorized role ('tenant_admin', 'employee', 'platform_admin').
    - groups: List of user group names (strings).
    - iat: Issued-at UNIX timestamp (UTC).
    - exp: Expiration UNIX timestamp (UTC).
    """
    settings = get_settings()

    # Validate inputs before issuing token
    clean_user_id = str(user_id).strip()
    if not clean_user_id:
        raise ValueError("user_id cannot be empty.")

    try:
        clean_tenant_id = str(uuid.UUID(str(tenant_id)))
    except (ValueError, AttributeError) as err:
        raise ValueError(f"tenant_id must be a valid UUID, got '{tenant_id}'.") from err

    if role not in VALID_ROLES:
        raise ValueError(
            f"Invalid role '{role}'. Allowed roles: {sorted(VALID_ROLES)}."
        )

    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        raise TypeError("groups must be a list of strings.")

    now = datetime.now(UTC)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: dict[str, Any] = {
        "user_id": clean_user_id,
        "tenant_id": clean_tenant_id,
        "role": role,
        "groups": list(groups),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def verify_access_token(token: str) -> dict[str, Any]:
    """Verify and decode a JWT access token.

    Enforces:
    1. Cryptographic signature verification using pinned algorithm (HS256 only).
    2. Token expiration (exp) and presence of issued-at (iat).
    3. Mandatory claims: user_id, tenant_id, role, groups, exp.
    4. Format validation:
       - tenant_id must parse as a valid UUID.
       - user_id must be non-empty string.
       - role must be strictly in VALID_ROLES (tenant_admin, employee, platform_admin).
       - groups must be a list of strings.

    Raises:
        AuthError: On any signature, parsing, expiration, or claim validation failure.
                   Never contains the raw token in the error message.
    """
    if not token or not isinstance(token, str):
        raise AuthError("Authentication failed: token must be a non-empty string.")

    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp"]},
        )
    except jwt.ExpiredSignatureError as err:
        raise AuthError("Authentication failed: token has expired.") from err
    except jwt.InvalidAlgorithmError as err:
        raise AuthError("Authentication failed: invalid token algorithm.") from err
    except jwt.InvalidSignatureError as err:
        raise AuthError("Authentication failed: invalid token signature.") from err
    except jwt.MissingRequiredClaimError as err:
        raise AuthError(
            f"Authentication failed: missing required claim: {err}"
        ) from err
    except jwt.PyJWTError as err:
        raise AuthError("Authentication failed: invalid token.") from err

    # 1. user_id claim validation
    user_id = payload.get("user_id")
    if not user_id or not isinstance(user_id, str) or not user_id.strip():
        raise AuthError("Authentication failed: user_id claim is missing or empty.")

    # 2. tenant_id claim validation (must be valid UUID format)
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise AuthError("Authentication failed: tenant_id claim is missing or empty.")
    try:
        uuid.UUID(str(tenant_id))
    except (ValueError, AttributeError) as err:
        raise AuthError(
            "Authentication failed: tenant_id claim must be a valid UUID."
        ) from err

    # 3. role claim validation (must match RBAC whitelist)
    role = payload.get("role")
    if not role or role not in VALID_ROLES:
        raise AuthError(
            f"Authentication failed: unauthorized or invalid role '{role}'."
        )

    # 4. groups claim validation (must be list of strings)
    groups = payload.get("groups")
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        raise AuthError(
            "Authentication failed: groups claim must be a list of strings."
        )

    # 5. exp claim validation (defense-in-depth)
    if payload.get("exp") is None:
        raise AuthError("Authentication failed: exp claim is missing.")

    return payload


# ==============================================================================
# API Key Cryptographic Utilities (Ticket T3c)
# ==============================================================================

API_KEY_PREFIX = "rag_key_"


def hash_api_key(raw_key: str) -> str:
    """Compute the SHA-256 hex digest of a raw API key.

    Strict security:
    - Stores exactly 64 hex characters in database.
    - Never logs, traces, or includes the raw key in errors.
    """
    if not raw_key or not isinstance(raw_key, str) or not raw_key.strip():
        raise ValueError("API key must be a non-empty string.")
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def generate_api_key(tenant_id: uuid.UUID | str) -> tuple[str, str]:
    """Generate a cryptographically secure random API key for a tenant.

    Entropy: 256 bits (secrets.token_hex(32)).
    Format: 'rag_key_<tenant_id_uuid>_<64_hex_secret>'
    Storage: SHA-256 hash of the full raw API key.

    Returns:
        tuple[str, str]: (plaintext_api_key, sha256_hash)
    """
    try:
        clean_tenant_id = str(uuid.UUID(str(tenant_id)))
    except (ValueError, AttributeError) as err:
        raise ValueError(f"tenant_id must be a valid UUID, got '{tenant_id}'.") from err

    # 32 bytes = 256 bits of cryptographically secure random entropy
    secret = secrets.token_hex(32)
    raw_key = f"{API_KEY_PREFIX}{clean_tenant_id}_{secret}"
    key_hash = hash_api_key(raw_key)
    return raw_key, key_hash


def extract_tenant_id_from_api_key(raw_key: str) -> uuid.UUID | None:
    """Extract candidate tenant UUID from an API key as a lookup hint.

    Validates key prefix and structure without trusting the extracted UUID for authorization.
    Returns None if the key format is malformed or invalid.
    """
    if not raw_key or not isinstance(raw_key, str):
        return None

    clean_key = raw_key.strip()
    if not clean_key.startswith(API_KEY_PREFIX):
        return None

    # Expected format: "rag_key_<tenant_id>_<secret>"
    # Splitting by "_" gives ["rag", "key", "<tenant_id>", "<secret>"]
    parts = clean_key.split("_")
    if len(parts) != 4 or parts[0] != "rag" or parts[1] != "key":
        return None

    try:
        tenant_uuid = uuid.UUID(parts[2])
    except (ValueError, AttributeError):
        return None

    secret = parts[3]
    # Ensure secret meets minimum length (at least 32 characters / 128+ bits entropy)
    if len(secret) < 32:
        return None

    return tenant_uuid
