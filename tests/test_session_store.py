"""Tests for session store."""

import pytest
from datetime import datetime, timedelta

from app.exceptions import SessionExpiredError, SessionNotFoundError
from app.models import CloudFrontCookies
from app.session_store import SessionStore


@pytest.fixture
def store():
    """Create a fresh session store for each test."""
    return SessionStore()


@pytest.fixture
def sample_cookies():
    """Sample CloudFront cookies."""
    return CloudFrontCookies(
        **{
            "CloudFront-Policy": "sample_policy_value",
            "CloudFront-Signature": "sample_signature_value",
            "CloudFront-Key-Pair-Id": "APKAXXXXX",
        }
    )


class TestSessionStore:
    """Test suite for session store."""

    def test_create_session(self, store, sample_cookies):
        """Test creating a new session."""
        base_url = "https://cdn.example.com/content/2025"

        session = store.create_session(
            base_url=base_url,
            cookies=sample_cookies,
            ttl=3600,
        )

        assert session.session_id.startswith("s_")
        assert session.token.startswith("t_")
        assert session.base_url == base_url
        assert "CloudFront-Policy" in session.cookies
        assert session.expires_at > session.created_at

    def test_get_session_by_token(self, store, sample_cookies):
        """Test retrieving session by token."""
        session = store.create_session(
            base_url="https://cdn.example.com/content/2025",
            cookies=sample_cookies,
        )

        retrieved = store.get_session_by_token(session.token)

        assert retrieved.session_id == session.session_id
        assert retrieved.token == session.token

    def test_get_session_by_id(self, store, sample_cookies):
        """Test retrieving session by session_id."""
        session = store.create_session(
            base_url="https://cdn.example.com/content/2025",
            cookies=sample_cookies,
        )

        retrieved = store.get_session_by_id(session.session_id)

        assert retrieved.session_id == session.session_id
        assert retrieved.token == session.token

    def test_session_not_found_by_token(self, store):
        """Test that nonexistent token raises error."""
        with pytest.raises(SessionNotFoundError):
            store.get_session_by_token("nonexistent_token")

    def test_session_not_found_by_id(self, store):
        """Test that nonexistent session_id raises error."""
        with pytest.raises(SessionNotFoundError):
            store.get_session_by_id("nonexistent_id")

    def test_refresh_session_cookies(self, store, sample_cookies):
        """Test refreshing CloudFront cookies."""
        session = store.create_session(
            base_url="https://cdn.example.com/content/2025",
            cookies=sample_cookies,
        )

        new_cookies = CloudFrontCookies(
            **{
                "CloudFront-Policy": "new_policy_value",
                "CloudFront-Signature": "new_signature_value",
                "CloudFront-Key-Pair-Id": "APKAXXXXX",
            }
        )

        refreshed = store.refresh_session_cookies(
            session_id=session.session_id,
            new_cookies=new_cookies,
        )

        assert refreshed.cookies["CloudFront-Policy"] == "new_policy_value"
        assert refreshed.cookies["CloudFront-Signature"] == "new_signature_value"
        assert refreshed.token == session.token  # Token should not change

    def test_delete_session(self, store, sample_cookies):
        """Test deleting a session."""
        session = store.create_session(
            base_url="https://cdn.example.com/content/2025",
            cookies=sample_cookies,
        )

        # Delete session
        deleted = store.delete_session(session.session_id)
        assert deleted is True

        # Verify it's gone
        with pytest.raises(SessionNotFoundError):
            store.get_session_by_id(session.session_id)

        with pytest.raises(SessionNotFoundError):
            store.get_session_by_token(session.token)

    def test_delete_nonexistent_session(self, store):
        """Test deleting a nonexistent session."""
        deleted = store.delete_session("nonexistent_id")
        assert deleted is False

    def test_session_count(self, store, sample_cookies):
        """Test getting session count."""
        assert store.get_session_count() == 0

        store.create_session("https://cdn.example.com/content/2025", sample_cookies)
        assert store.get_session_count() == 1

        store.create_session("https://cdn.example.com/content/2026", sample_cookies)
        assert store.get_session_count() == 2

    def test_ttl_enforcement(self, store, sample_cookies):
        """Test that TTL is enforced within max limits."""
        # Request TTL beyond max
        session = store.create_session(
            base_url="https://cdn.example.com/content/2025",
            cookies=sample_cookies,
            ttl=100000,  # Way beyond max
        )

        # Should be capped at max TTL
        duration = (session.expires_at - session.created_at).total_seconds()
        assert duration <= 21600  # Max TTL from config

    def test_unique_session_ids_and_tokens(self, store, sample_cookies):
        """Test that each session gets unique IDs and tokens."""
        session1 = store.create_session("https://cdn.example.com/content/2025", sample_cookies)
        session2 = store.create_session("https://cdn.example.com/content/2025", sample_cookies)

        assert session1.session_id != session2.session_id
        assert session1.token != session2.token

    def test_last_accessed_updated_on_retrieval(self, store, sample_cookies):
        """Test that last_accessed is updated when retrieving session."""
        session = store.create_session("https://cdn.example.com/content/2025", sample_cookies)
        original_last_accessed = session.last_accessed

        # Small delay and retrieve
        import time

        time.sleep(0.1)

        retrieved = store.get_session_by_token(session.token)

        assert retrieved.last_accessed > original_last_accessed
