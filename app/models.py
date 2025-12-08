"""Data models for the proxy server."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class CloudFrontCookies(BaseModel):
    """CloudFront signed cookies required for authentication."""

    CloudFront_Policy: str = Field(..., alias="CloudFront-Policy")
    CloudFront_Signature: str = Field(..., alias="CloudFront-Signature")
    CloudFront_Key_Pair_Id: str = Field(..., alias="CloudFront-Key-Pair-Id")

    model_config = {"populate_by_name": True}

    def to_cookie_dict(self) -> dict[str, str]:
        """Convert to dictionary format for HTTP Cookie header."""
        return {
            "CloudFront-Policy": self.CloudFront_Policy,
            "CloudFront-Signature": self.CloudFront_Signature,
            "CloudFront-Key-Pair-Id": self.CloudFront_Key_Pair_Id,
        }

    @field_validator("CloudFront_Policy", "CloudFront_Signature", "CloudFront_Key_Pair_Id")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure cookie values are not empty."""
        if not v or not v.strip():
            raise ValueError("Cookie value cannot be empty")
        return v.strip()


class CreateSessionRequest(BaseModel):
    """Request body for creating a new session."""

    base_url: HttpUrl = Field(..., description="CloudFront base URL for the stream")
    cookies: CloudFrontCookies = Field(..., description="CloudFront signed cookies")
    ttl: Optional[int] = Field(
        None,
        ge=60,
        le=21600,
        description="Session TTL in seconds (60s to 6 hours)",
    )

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: HttpUrl) -> HttpUrl:
        """Ensure base_url uses HTTPS."""
        if v.scheme != "https":
            raise ValueError("base_url must use HTTPS protocol")
        return v


class RefreshSessionRequest(BaseModel):
    """Request body for refreshing session cookies."""

    cookies: CloudFrontCookies = Field(..., description="Updated CloudFront signed cookies")


class SessionResponse(BaseModel):
    """Response for session creation."""

    session_id: str = Field(..., description="Session ID for management operations")
    token: str = Field(..., description="Authentication token for streaming requests")
    expires_at: datetime = Field(..., description="Session expiration timestamp")


class RefreshSessionResponse(BaseModel):
    """Response for session refresh."""

    session_id: str = Field(..., description="Session ID")
    expires_at: datetime = Field(..., description="Updated expiration timestamp")
    updated: bool = Field(True, description="Whether the update was successful")


class SessionData(BaseModel):
    """Internal session data structure."""

    session_id: str
    token: str
    base_url: str  # CloudFront base URL (e.g., "https://cdn.example.com/content/2025")
    cookies: dict[str, str]  # CloudFront cookies as dict
    created_at: datetime
    expires_at: datetime
    last_accessed: datetime
    metadata: Optional[dict] = None

    def is_expired(self, current_time: datetime) -> bool:
        """Check if the session has expired."""
        return current_time >= self.expires_at

    def update_last_accessed(self, current_time: datetime) -> None:
        """Update the last accessed timestamp."""
        self.last_accessed = current_time
