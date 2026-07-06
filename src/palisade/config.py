"""Application configuration loaded from the environment.

All external-service credentials are optional so the app boots without them;
they are required only by the ingestion/scan features added in later PRs.
Secret fields are SecretStr: read them with `.get_secret_value()` at the call site.
"""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "palisade"
    environment: str = "local"

    database_url: str = "postgresql+psycopg://palisade:palisade@localhost:5432/palisade"

    # External API auth (optional; needed by ingestion/scan in later PRs).
    nvd_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    github_webhook_secret: SecretStr | None = None  # HMAC secret for the PR-scan webhook (M3)
    anthropic_api_key: SecretStr | None = None

    # Model routing (see IMPLEMENTATION_PLAN.md section 6).
    strong_model: str = "claude-opus-4-8"
    cheap_model: str = "claude-haiku-4-5-20251001"

    # Advisory-corpus embeddings (see IMPLEMENTATION_PLAN.md sections 4.1 / 5).
    # embedding_dim must match the advisory_embeddings vector column; changing it
    # requires a new migration.
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dim: int = 384

    # Observability (optional). The public key is public by design; the secret key is a secret.
    langfuse_public_key: str | None = None
    langfuse_secret_key: SecretStr | None = None
    langfuse_host: str = "https://cloud.langfuse.com"

    # M3 scan-queue worker (see IMPLEMENTATION_PLAN.md §M3).
    worker_poll_interval: float = 1.0  # seconds to sleep when the queue is empty
    worker_stale_seconds: int = 900  # startup: reclaim 'running' rows older than this


@lru_cache
def get_settings() -> Settings:
    return Settings()
