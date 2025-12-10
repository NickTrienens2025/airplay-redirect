"""Tests for API endpoints."""

import base64
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _encode_cloudfront_base64(data: bytes) -> str:
    """Encode data using CloudFront's URL-safe base64."""
    encoded = base64.b64encode(data).decode("utf-8")
    # CloudFront uses: - instead of +, _ instead of =, ~ instead of /
    return encoded.replace("+", "-").replace("=", "_").replace("/", "~")


def _make_valid_policy() -> str:
    """Create a valid CloudFront policy for testing."""
    policy = {
        "Statement": [
            {
                "Resource": "https://example.cloudfront.net/*",
                "Condition": {
                    "DateLessThan": {"AWS:EpochTime": 9999999999}
                }
            }
        ]
    }
    return _encode_cloudfront_base64(json.dumps(policy).encode("utf-8"))


def _make_valid_signature() -> str:
    """Create a valid-looking CloudFront signature for testing (128 bytes when decoded)."""
    # Generate 128 bytes of fake signature data
    fake_sig = b"x" * 128
    return _encode_cloudfront_base64(fake_sig)


def _valid_cookies() -> dict:
    """Return valid CloudFront cookies for testing."""
    return {
        "CloudFront-Policy": _make_valid_policy(),
        "CloudFront-Signature": _make_valid_signature(),
        "CloudFront-Key-Pair-Id": "K2ABCDEFGHIJ",
    }


class TestSessionEndpoints:
    """Test suite for session management endpoints."""

    def test_create_session(self):
        """Test creating a new session."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": _valid_cookies(),
                "ttl": 3600,
            },
        )

        assert response.status_code == 201
        data = response.json()

        assert "session_id" in data
        assert "token" in data
        assert "expires_at" in data
        assert data["session_id"].startswith("s_")
        assert data["token"].startswith("t_")

    def test_create_session_empty_cookies(self):
        """Test creating session with empty cookie value."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": {
                    "CloudFront-Policy": "",  # Empty value
                    "CloudFront-Signature": _make_valid_signature(),
                    "CloudFront-Key-Pair-Id": "K2ABCDEFGHIJ",
                },
            },
        )

        assert response.status_code == 422  # Validation error

    def test_create_session_invalid_policy_format(self):
        """Test that corrupted policy format is rejected."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": {
                    "CloudFront-Policy": "CORRUPTED_POLICY",  # Invalid base64/JSON
                    "CloudFront-Signature": _make_valid_signature(),
                    "CloudFront-Key-Pair-Id": "K2ABCDEFGHIJ",
                },
            },
        )

        assert response.status_code == 422  # Validation error
        assert "Invalid CloudFront-Policy" in response.text

    def test_create_session_invalid_signature_format(self):
        """Test that corrupted signature format is rejected."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": {
                    "CloudFront-Policy": _make_valid_policy(),
                    "CloudFront-Signature": "CORRUPTED_SIGNATURE",  # Too short when decoded
                    "CloudFront-Key-Pair-Id": "K2ABCDEFGHIJ",
                },
            },
        )

        assert response.status_code == 422  # Validation error
        assert "Invalid CloudFront-Signature" in response.text

    def test_create_session_invalid_key_pair_id(self):
        """Test that invalid Key-Pair-Id format is rejected."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": {
                    "CloudFront-Policy": _make_valid_policy(),
                    "CloudFront-Signature": _make_valid_signature(),
                    "CloudFront-Key-Pair-Id": "INVALID",  # Too short
                },
            },
        )

        assert response.status_code == 422  # Validation error
        assert "Invalid CloudFront-Key-Pair-Id" in response.text

    def test_create_session_http_url(self):
        """Test that HTTP URLs are rejected (HTTPS required)."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "http://cdn.example.com/content/2025",  # HTTP not HTTPS
                "cookies": _valid_cookies(),
            },
        )

        assert response.status_code == 422

    def test_delete_session(self):
        """Test deleting a session."""
        # Create session
        create_response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": _valid_cookies(),
            },
        )

        session_id = create_response.json()["session_id"]

        # Delete session
        delete_response = client.delete(f"/api/v1/session/{session_id}")

        assert delete_response.status_code == 204

    def test_health_check(self):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "sessions" in data
        assert "version" in data

    def test_root_endpoint(self):
        """Test root endpoint returns HTML."""
        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        # HTML should contain service info
        assert "AirPlay-CloudFront HLS Proxy" in response.text
