from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Config
    APP_ENV: str = "development"
    APP_NAME: str = "Multi-Tenant Enterprise RAG Platform"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True
    PORT: int = 8000

    # Security
    SECRET_KEY: str = "change-this-to-a-super-secret-random-key-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # PostgreSQL
    POSTGRES_USER: str = "rag_user"
    POSTGRES_PASSWORD: str = "rag_secure_password"
    POSTGRES_DB: str = "rag_enterprise_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = (
        "postgresql+asyncpg://rag_user:rag_secure_password@localhost:5432/rag_enterprise_db"
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
