"""app/core/config.py — Application configuration & environment settings.

Ticket T3 Hardening:
- Pydantic v2 settings with strict validation.
- Pinned HS256 algorithm and minimum 32-byte JWT_SECRET_KEY.
- Strict production validation when APP_ENV=production:
  - DEBUG must be False.
  - Development placeholders rejected for SECRET_KEY, JWT_SECRET_KEY, DB passwords, MinIO.
  - Consistent URL credentials enforced.
  - Secret values masked in repr to prevent log leakage.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import unquote, urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "change-this-to-a-super-secret-random-key-in-production",
        "change-this-to-a-super-secret-jwt-key-with-at-least-32-bytes-in-production",
        "rag_secure_password",
        "rag_app_password",
        "minioadmin",
        "secret",
        "password",
    }
)


class Settings(BaseSettings):
    # Application Config
    APP_ENV: str = "development"
    APP_NAME: str = "Multi-Tenant Enterprise RAG Platform"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True
    PORT: int = 8000

    # Security & Authentication (Ticket T3)
    SECRET_KEY: str = "change-this-to-a-super-secret-random-key-in-production"
    JWT_SECRET_KEY: str = (
        "change-this-to-a-super-secret-jwt-key-with-at-least-32-bytes-in-production"
    )
    JWT_ALGORITHM: Literal["HS256"] = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret_key(cls, v: str) -> str:
        """Validate that JWT_SECRET_KEY is at least 32 bytes (256 bits for HS256)."""
        if not v or len(v.encode("utf-8")) < 32:
            raise ValueError(
                "JWT_SECRET_KEY must be provided and must be at least 32 bytes (256 bits) for HS256 security."
            )
        return v

    # PostgreSQL - Migration / Admin connection (used by Alembic migrations)
    POSTGRES_USER: str = "rag_user"
    POSTGRES_PASSWORD: str = "rag_secure_password"
    POSTGRES_DB: str = "rag_enterprise_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5433
    DATABASE_URL: str = (
        "postgresql+asyncpg://rag_user:rag_secure_password@localhost:5433/rag_enterprise_db"
    )

    # PostgreSQL - Application Runtime Role (NOSUPERUSER, NOBYPASSRLS, used by API engine)
    POSTGRES_APP_USER: str = "rag_app"
    POSTGRES_APP_PASSWORD: str = "rag_app_password"
    APP_DATABASE_URL: str = (
        "postgresql+asyncpg://rag_app:rag_app_password@localhost:5433/rag_enterprise_db"
    )

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_URL: str = "redis://localhost:6379/0"

    # MinIO
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ROOT_USER: str = "minioadmin"
    MINIO_ROOT_PASSWORD: str = "minioadmin"
    MINIO_BUCKET_DOCUMENTS: str = "tenant-documents"
    MINIO_SECURE: bool = False

    # Model settings
    DEFAULT_EMBEDDING_MODEL: str = "BAAI/bge-small-en-v1.5"
    LLM_PROVIDER: str = "openai"
    LLM_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_production_settings(self) -> Settings:
        """Enforce strict production configuration validation when APP_ENV=production."""
        if self.APP_ENV.lower() != "production":
            return self

        # 1. DEBUG must be False
        if self.DEBUG:
            raise ValueError("DEBUG must be set to False in production.")

        # 2. SECRET_KEY validation
        if (
            not self.SECRET_KEY
            or len(self.SECRET_KEY.encode("utf-8")) < 32
            or self.SECRET_KEY in DEV_PLACEHOLDERS
            or "change-this" in self.SECRET_KEY.lower()
        ):
            raise ValueError(
                "In production, SECRET_KEY must be a unique, strong secret of at least 32 bytes."
            )

        # 3. JWT_SECRET_KEY validation
        if (
            self.JWT_SECRET_KEY in DEV_PLACEHOLDERS
            or "change-this" in self.JWT_SECRET_KEY.lower()
        ):
            raise ValueError(
                "In production, JWT_SECRET_KEY cannot use development placeholder values."
            )

        # 4. Database credentials validation
        if (
            self.POSTGRES_PASSWORD in DEV_PLACEHOLDERS
            or "rag_secure_password" in self.POSTGRES_PASSWORD
        ):
            raise ValueError(
                "In production, POSTGRES_PASSWORD cannot use default development credentials."
            )

        if (
            self.POSTGRES_APP_PASSWORD in DEV_PLACEHOLDERS
            or "rag_app_password" in self.POSTGRES_APP_PASSWORD
        ):
            raise ValueError(
                "In production, POSTGRES_APP_PASSWORD cannot use default development credentials."
            )

        # 5. MinIO credentials validation
        if (
            self.MINIO_ROOT_USER == "minioadmin"
            or self.MINIO_ROOT_PASSWORD == "minioadmin"
            or self.MINIO_ROOT_PASSWORD in DEV_PLACEHOLDERS
        ):
            raise ValueError(
                "In production, MinIO cannot use default credentials (minioadmin)."
            )

        # 6. Database and role consistency validation against infrastructure (infra/postgres/roles.sql)
        if self.POSTGRES_USER == self.POSTGRES_APP_USER:
            raise ValueError(
                "In production, migration owner (POSTGRES_USER) and runtime application role (POSTGRES_APP_USER) must remain separate."
            )

        if self.POSTGRES_APP_USER != "rag_app":
            raise ValueError(
                "In production, POSTGRES_APP_USER must match supported role 'rag_app' provisioned by infrastructure."
            )

        if self.POSTGRES_USER != "rag_user":
            raise ValueError(
                "In production, POSTGRES_USER must match supported migration owner 'rag_user' provisioned by infrastructure."
            )

        if self.POSTGRES_DB != "rag_enterprise_db":
            raise ValueError(
                "In production, POSTGRES_DB must match supported database 'rag_enterprise_db' provisioned by infrastructure."
            )

        # 7. Database URL validation (APP_DATABASE_URL and DATABASE_URL)
        valid_schemes = ("postgresql", "postgresql+asyncpg", "postgresql+psycopg2")

        for url_name, raw_url, expected_user, expected_pwd in [
            (
                "APP_DATABASE_URL",
                self.APP_DATABASE_URL,
                self.POSTGRES_APP_USER,
                self.POSTGRES_APP_PASSWORD,
            ),
            (
                "DATABASE_URL",
                self.DATABASE_URL,
                self.POSTGRES_USER,
                self.POSTGRES_PASSWORD,
            ),
        ]:
            if not raw_url or not isinstance(raw_url, str):
                raise ValueError(
                    f"{url_name} must be a non-empty URL string in production."
                )

            try:
                parsed = urlparse(raw_url)
            except Exception as err:
                raise ValueError(
                    f"{url_name} is malformed or cannot be parsed."
                ) from err

            # Validate scheme
            if not parsed.scheme or not (
                parsed.scheme in valid_schemes or parsed.scheme.startswith("postgresql")
            ):
                raise ValueError(
                    f"{url_name} scheme must be a valid PostgreSQL scheme."
                )

            # Validate host
            if not parsed.hostname:
                raise ValueError(f"{url_name} must include a valid host.")

            # Validate database path
            db_path = parsed.path.lstrip("/")
            if not db_path:
                raise ValueError(f"{url_name} must specify a database name.")
            if db_path != self.POSTGRES_DB:
                raise ValueError(
                    f"{url_name} database name is inconsistent with POSTGRES_DB."
                )

            # Validate username
            if not parsed.username:
                raise ValueError(f"{url_name} must contain a username.")
            if unquote(parsed.username) != expected_user:
                raise ValueError(
                    f"{url_name} username is inconsistent with configured database user."
                )

            # Validate password
            if not parsed.password:
                raise ValueError(f"{url_name} must contain a password.")
            if unquote(parsed.password) != expected_pwd:
                raise ValueError(
                    f"{url_name} password is inconsistent with configured database password."
                )

        return self

    def __repr__(self) -> str:
        """Mask sensitive secrets in string representation to prevent accidental log leakage."""
        return (
            f"Settings(APP_ENV={self.APP_ENV!r}, APP_NAME={self.APP_NAME!r}, "
            f"DEBUG={self.DEBUG!r}, PORT={self.PORT!r}, "
            f"POSTGRES_USER={self.POSTGRES_USER!r}, POSTGRES_APP_USER={self.POSTGRES_APP_USER!r}, "
            f"JWT_ALGORITHM={self.JWT_ALGORITHM!r}, ... [secrets masked])"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
