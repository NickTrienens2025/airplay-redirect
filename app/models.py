"""Data models for the proxy server."""

import base64
import json
import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator


def _decode_cloudfront_base64(value: str) -> bytes:
    """
    Decode CloudFront's URL-safe base64 encoding.
    
    CloudFront uses a modified base64 encoding:
    - `-` instead of `+`
    - `_` instead of `=` (padding)
    - `~` instead of `/`
    """
    # Convert CloudFront's URL-safe chars back to standard base64
    standard_b64 = value.replace("-", "+").replace("_", "=").replace("~", "/")
    
    # Add padding if needed
    padding = 4 - (len(standard_b64) % 4)
    if padding != 4:
        standard_b64 += "=" * padding
    
    return base64.b64decode(standard_b64)


class CloudFrontCookies(BaseModel):
    """CloudFront signed cookies required for authentication."""

    CloudFront_Policy: str = Field(..., alias="CloudFront-Policy")
    CloudFront_Signature: str = Field(..., alias="CloudFront-Signature")
    CloudFront_Key_Pair_Id: str = Field(..., alias="CloudFront-Key-Pair-Id")

    model_config = {"populate_by_name": True}

    @classmethod
    def create_demo(cls) -> "CloudFrontCookies":
        """Create demo cookies that bypass validation (for internal demo streams)."""
        return cls.model_construct(
            CloudFront_Policy="demo",
            CloudFront_Signature="demo",
            CloudFront_Key_Pair_Id="demo",
        )

    def to_cookie_dict(self) -> dict[str, str]:
        """Convert to dictionary format for HTTP Cookie header."""
        return {
            "CloudFront-Policy": self.CloudFront_Policy,
            "CloudFront-Signature": self.CloudFront_Signature,
            "CloudFront-Key-Pair-Id": self.CloudFront_Key_Pair_Id,
        }

    @field_validator("CloudFront_Policy", "CloudFront_Signature", "CloudFront_Key_Pair_Id", mode="before")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure cookie values are not empty."""
        if not v or not v.strip():
            raise ValueError("Cookie value cannot be empty")
        return v.strip()

    @field_validator("CloudFront_Key_Pair_Id")
    @classmethod
    def validate_key_pair_id(cls, v: str) -> str:
        """
        Validate CloudFront Key Pair ID format.
        
        Key Pair IDs are typically alphanumeric strings starting with 'K' or 'APK'.
        Example: KXXXXXXXXXXXX or APKXXXXXXXXXXX
        """
        if not re.match(r"^[A-Z0-9]{10,20}$", v, re.IGNORECASE):
            raise ValueError(
                f"Invalid CloudFront-Key-Pair-Id format: '{v}'. "
                "Expected alphanumeric string (10-20 chars, e.g., 'K2XXXXXXX')"
            )
        return v

    @field_validator("CloudFront_Policy")
    @classmethod
    def validate_policy_format(cls, v: str) -> str:
        """
        Validate CloudFront Policy is valid base64-encoded JSON with required fields.
        
        A valid policy must decode to JSON containing a "Statement" array.
        """
        try:
            decoded = _decode_cloudfront_base64(v)
            policy = json.loads(decoded)
            
            # Check for required "Statement" field
            if "Statement" not in policy:
                raise ValueError(
                    "Invalid CloudFront-Policy: decoded JSON must contain 'Statement' field"
                )
            
            # Statement should be a list
            if not isinstance(policy["Statement"], list):
                raise ValueError(
                    "Invalid CloudFront-Policy: 'Statement' must be an array"
                )
            
            # Check at least one statement exists
            if len(policy["Statement"]) == 0:
                raise ValueError(
                    "Invalid CloudFront-Policy: 'Statement' array cannot be empty"
                )
            
            return v
            
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Invalid CloudFront-Policy: not valid base64-encoded JSON. {e}"
            )
        except Exception as e:
            if "Invalid CloudFront-Policy" in str(e):
                raise
            raise ValueError(
                f"Invalid CloudFront-Policy: failed to decode - {e}"
            )

    @field_validator("CloudFront_Signature")
    @classmethod
    def validate_signature_format(cls, v: str) -> str:
        """
        Validate CloudFront Signature is valid base64 encoding.
        
        The signature should decode to binary data (RSA signature).
        """
        try:
            decoded = _decode_cloudfront_base64(v)
            
            # RSA-SHA1 signature should be at least 128 bytes (1024-bit key minimum)
            if len(decoded) < 64:
                raise ValueError(
                    f"Invalid CloudFront-Signature: decoded length ({len(decoded)} bytes) "
                    "is too short for a valid RSA signature"
                )
            
            return v
            
        except Exception as e:
            if "Invalid CloudFront-Signature" in str(e):
                raise
            raise ValueError(
                f"Invalid CloudFront-Signature: not valid base64 encoding - {e}"
            )


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
    validate_path: Optional[str] = Field(
        None,
        description="Optional M3U8 path to validate cookies work (e.g., 'index.m3u8')",
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


class ValidationResult(BaseModel):
    """Result of M3U8 validation during session creation."""

    validated: bool = Field(..., description="Whether validation was performed")
    success: bool = Field(..., description="Whether validation succeeded")
    status_code: Optional[int] = Field(None, description="HTTP status code from CloudFront")
    error: Optional[str] = Field(None, description="Error message if validation failed")


class SessionResponse(BaseModel):
    """Response for session creation."""

    session_id: str = Field(..., description="Session ID for management operations")
    token: str = Field(..., description="Authentication token for streaming requests")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    validation: Optional[ValidationResult] = Field(None, description="M3U8 validation result")


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
