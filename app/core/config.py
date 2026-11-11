from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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


@lru_cache
def get_settings() -> Settings:
    return Settings()
