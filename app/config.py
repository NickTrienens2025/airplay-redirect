"""Configuration management for the proxy server."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Session Configuration
    session_ttl_seconds: int = 3600  # 1 hour default
    session_max_ttl_seconds: int = 21600  # 6 hours max
    session_idle_timeout_seconds: int = 1800  # 30 minutes

    # CloudFront Configuration
    allowed_cloudfront_domains: str = ""  # Comma-separated list

    # Demo Stream Configuration
    demo_stream_enabled: bool = True
    demo_stream_url: str = "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"  # Big Buck Bunny test stream
    demo_stream_base_url: str = "https://test-streams.mux.dev/x36xhzz"  # Base URL for the demo stream

    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # HTTP Client Configuration
    http_timeout_seconds: float = 30.0
    http_max_connections: int = 100
    http_max_keepalive_connections: int = 20

    @property
    def allowed_domains_list(self) -> list[str]:
        """Parse allowed domains from comma-separated string."""
        if not self.allowed_cloudfront_domains:
            return []
        return [d.strip() for d in self.allowed_cloudfront_domains.split(",") if d.strip()]


# Global settings instance
settings = Settings()
