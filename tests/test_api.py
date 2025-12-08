"""Tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestSessionEndpoints:
    """Test suite for session management endpoints."""

    def test_create_session(self):
        """Test creating a new session."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": {
                    "CloudFront-Policy": "test_policy",
                    "CloudFront-Signature": "test_signature",
                    "CloudFront-Key-Pair-Id": "APKAXXXXX",
                },
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

    def test_create_session_invalid_cookies(self):
        """Test creating session with invalid cookies."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "https://cdn.example.com/content/2025",
                "cookies": {
                    "CloudFront-Policy": "",  # Empty value
                    "CloudFront-Signature": "test_signature",
                    "CloudFront-Key-Pair-Id": "APKAXXXXX",
                },
            },
        )

        assert response.status_code == 422  # Validation error

    def test_create_session_http_url(self):
        """Test that HTTP URLs are rejected (HTTPS required)."""
        response = client.post(
            "/api/v1/session/create",
            json={
                "base_url": "http://cdn.example.com/content/2025",  # HTTP not HTTPS
                "cookies": {
                    "CloudFront-Policy": "test_policy",
                    "CloudFront-Signature": "test_signature",
                    "CloudFront-Key-Pair-Id": "APKAXXXXX",
                },
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
                "cookies": {
                    "CloudFront-Policy": "test_policy",
                    "CloudFront-Signature": "test_signature",
                    "CloudFront-Key-Pair-Id": "APKAXXXXX",
                },
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
        """Test root endpoint."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()

        assert "service" in data
        assert "version" in data
        assert "docs" in data
