"""
NetSpecter Configuration Module

Centralized configuration management using pydantic-settings.
Loads settings from environment variables and .env files.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Find the project root (where .env is located)
_PROJECT_ROOT = Path(__file__).parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ==========================================================================
    # Server Configuration
    # ==========================================================================
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    debug: bool = Field(default=False, description="Debug mode")

    # ==========================================================================
    # API Keys
    # ==========================================================================
    openrouter_api_key: str = Field(
        default="",
        description="OpenRouter API key for LLM access",
    )
    virustotal_api_key: str = Field(
        default="",
        description="VirusTotal API key",
    )
    abuseipdb_api_key: str = Field(
        default="",
        description="AbuseIPDB API key",
    )
    otx_api_key: str = Field(
        default="",
        description="AlienVault OTX API key",
    )

    # ==========================================================================
    # Analysis Configuration
    # ==========================================================================
    max_upload_size: int = Field(
        default=10 * 1024 * 1024 * 1024,  # 10GB
        description="Maximum file size for uploads (bytes)",
    )
    packet_batch_size: int = Field(
        default=10000,
        description="Number of packets to process per batch",
    )
    memory_threshold: int = Field(
        default=1024 * 1024 * 1024,  # 1GB
        description="Memory threshold before temp file fallback (bytes)",
    )
    cache_ttl_seconds: int = Field(
        default=86400,  # 24 hours
        description="Threat intel cache TTL in seconds",
    )

    # ==========================================================================
    # Logging Configuration
    # ==========================================================================
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    log_format: Literal["json", "console"] = Field(
        default="json",
        description="Log output format",
    )

    # ==========================================================================
    # LLM Model Configuration
    # ==========================================================================
    # Using DeepSeek reasoning models (free tier)
    # These are slower but produce higher quality security analysis
    llm_model_stats: str = Field(
        default="deepseek/deepseek-r1-0528:free",
        description="Model for statistical analysis (Phase 1)",
    )
    llm_model_detection: str = Field(
        default="tngtech/deepseek-r1t-chimera:free",
        description="Model for detection analysis (Phase 2)",
    )
    llm_model_synthesis: str = Field(
        default="deepseek/deepseek-r1-0528:free",
        description="Model for final synthesis",
    )
    llm_model_fast: str = Field(
        default="arcee-ai/trinity-large-preview:free",
        description="Fast model for quick decisions (e.g., VT prioritization)",
    )

    # LLM timeout settings (reasoning models can take 60-180s)
    llm_timeout_default: int = Field(
        default=180,
        description="Default timeout for LLM requests (seconds)",
    )
    llm_timeout_reasoning: int = Field(
        default=300,
        description="Extended timeout for reasoning models (seconds)",
    )

    # ==========================================================================
    # Paths
    # ==========================================================================
    temp_dir: Path = Field(
        default=Path("/tmp/netspecter"),
        description="Temporary directory for intermediate files",
    )

    @field_validator("temp_dir", mode="before")
    @classmethod
    def ensure_path(cls, v: str | Path) -> Path:
        """Ensure temp_dir is a Path object."""
        return Path(v) if isinstance(v, str) else v

    # ==========================================================================
    # Computed Properties
    # ==========================================================================
    @property
    def has_openrouter(self) -> bool:
        """Check if OpenRouter API key is configured."""
        return bool(self.openrouter_api_key)

    @property
    def has_virustotal(self) -> bool:
        """Check if VirusTotal API key is configured."""
        return bool(self.virustotal_api_key)

    @property
    def has_abuseipdb(self) -> bool:
        """Check if AbuseIPDB API key is configured."""
        return bool(self.abuseipdb_api_key)

    @property
    def has_otx(self) -> bool:
        """Check if AlienVault OTX API key is configured."""
        return bool(self.otx_api_key)

    @property
    def threat_intel_enabled(self) -> bool:
        """Check if any threat intelligence API is configured."""
        return self.has_virustotal or self.has_abuseipdb or self.has_otx

    def ensure_temp_dir(self) -> Path:
        """Create temp directory if it doesn't exist."""
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        return self.temp_dir


@lru_cache
def get_settings() -> Settings:
    """
    Get cached application settings.

    Uses lru_cache to ensure settings are only loaded once.
    """
    return Settings()


# Convenience alias
settings = get_settings()
