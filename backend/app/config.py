from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables and a local `.env`.

    Attributes:
        virustotal_api_key: Credential for VirusTotal. Lookups require it.
        abuseipdb_api_key: Credential for AbuseIPDB. When empty, IP reports omit
            the AbuseIPDB section.
        cache_ttl_seconds: How long a provider response stays servable from cache.
        request_timeout_seconds: Per-request timeout applied to provider calls.
        cors_origins: Origins allowed to call the API from a browser.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    virustotal_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("VT_API_KEY", "VIRUSTOTAL_API_KEY"),
    )
    abuseipdb_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("ABUSEIPDB_API_KEY"),
    )

    cache_ttl_seconds: int = 900
    request_timeout_seconds: float = 20.0

    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    @property
    def virustotal_configured(self) -> bool:
        """Whether a VirusTotal credential is available."""
        return bool(self.virustotal_api_key.strip())

    @property
    def abuseipdb_configured(self) -> bool:
        """Whether an AbuseIPDB credential is available."""
        return bool(self.abuseipdb_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
