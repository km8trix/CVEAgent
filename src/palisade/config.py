"""Application configuration loaded from the environment.

All external-service credentials are optional so the app boots without them;
they are required only by the ingestion/scan features added in later PRs.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "palisade"
    environment: str = "local"

    database_url: str = "postgresql+psycopg://palisade:palisade@localhost:5432/palisade"

    # External API auth (optional; needed by ingestion/scan in later PRs).
    nvd_api_key: str | None = None
    github_token: str | None = None
    anthropic_api_key: str | None = None

    # Model routing (see IMPLEMENTATION_PLAN.md section 6).
    strong_model: str = "claude-opus-4-8"
    cheap_model: str = "claude-haiku-4-5-20251001"

    # Observability (optional).
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None
    langfuse_host: str = "https://cloud.langfuse.com"


@lru_cache
def get_settings() -> Settings:
    return Settings()
