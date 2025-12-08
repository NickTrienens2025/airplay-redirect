"""Thread-safe in-memory session store."""

import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from app.config import settings
from app.exceptions import InvalidDomainError, SessionExpiredError, SessionNotFoundError
from app.models import CloudFrontCookies, SessionData


class SessionStore:
    """Thread-safe in-memory session store with dual lookup (session_id and token)."""

    def __init__(self):
        """Initialize the session store with thread-safe locks."""
        self._sessions_by_id: dict[str, SessionData] = {}
        self._sessions_by_token: dict[str, SessionData] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested locking

    def _generate_id(self, prefix: str) -> str:
        """Generate a cryptographically secure random ID with prefix."""
        return f"{prefix}_{secrets.token_urlsafe(16)}"

    def _validate_domain(self, base_url: str) -> None:
        """Validate that the base_url domain is in the allowed list."""
        if not settings.allowed_domains_list:
            # If no domains configured, allow all (dev mode)
            return

        parsed = urlparse(base_url)
        domain = parsed.netloc

        if domain not in settings.allowed_domains_list:
            raise InvalidDomainError(domain)

    def create_session(
        self,
        base_url: str,
        cookies: CloudFrontCookies,
        ttl: Optional[int] = None,
    ) -> SessionData:
        """
        Create a new session with CloudFront cookies.

        Args:
            base_url: CloudFront base URL (e.g., "https://cdn.example.com/content/2025")
            cookies: CloudFront signed cookies
            ttl: Optional session TTL in seconds (defaults to config value)

        Returns:
            SessionData with generated session_id and token

        Raises:
            InvalidDomainError: If base_url domain is not allowed
        """
        # Validate domain
        self._validate_domain(base_url)

        # Determine TTL
        if ttl is None:
            ttl = settings.session_ttl_seconds
        else:
            # Enforce maximum TTL
            ttl = min(ttl, settings.session_max_ttl_seconds)

        # Generate IDs
        session_id = self._generate_id("s")
        token = self._generate_id("t")

        # Create session data
        now = datetime.now(timezone.utc)
        session_data = SessionData(
            session_id=session_id,
            token=token,
            base_url=str(base_url),
            cookies=cookies.to_cookie_dict(),
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            last_accessed=now,
        )

        # Store with dual lookup
        with self._lock:
            self._sessions_by_id[session_id] = session_data
            self._sessions_by_token[token] = session_data

        return session_data

    def get_session_by_token(self, token: str) -> SessionData:
        """
        Retrieve session by token and validate it's not expired.

        Args:
            token: Authentication token

        Returns:
            SessionData if valid

        Raises:
            SessionNotFoundError: If token doesn't exist
            SessionExpiredError: If session has expired
        """
        with self._lock:
            session = self._sessions_by_token.get(token)

            if session is None:
                raise SessionNotFoundError(f"token:{token}")

            # Check expiration
            now = datetime.now(timezone.utc)
            if session.is_expired(now):
                # Clean up expired session
                self._remove_session(session)
                raise SessionExpiredError()

            # Update last accessed
            session.update_last_accessed(now)

            return session

    def get_session_by_id(self, session_id: str) -> SessionData:
        """
        Retrieve session by session_id.

        Args:
            session_id: Session identifier

        Returns:
            SessionData if valid

        Raises:
            SessionNotFoundError: If session_id doesn't exist
            SessionExpiredError: If session has expired
        """
        with self._lock:
            session = self._sessions_by_id.get(session_id)

            if session is None:
                raise SessionNotFoundError(f"session_id:{session_id}")

            # Check expiration
            now = datetime.now(timezone.utc)
            if session.is_expired(now):
                # Clean up expired session
                self._remove_session(session)
                raise SessionExpiredError()

            return session

    def refresh_session_cookies(
        self,
        session_id: str,
        new_cookies: CloudFrontCookies,
    ) -> SessionData:
        """
        Update the CloudFront cookies for an existing session.

        Args:
            session_id: Session identifier
            new_cookies: New CloudFront signed cookies

        Returns:
            Updated SessionData

        Raises:
            SessionNotFoundError: If session doesn't exist
            SessionExpiredError: If session has expired
        """
        with self._lock:
            session = self.get_session_by_id(session_id)

            # Update cookies (token remains the same)
            session.cookies = new_cookies.to_cookie_dict()
            session.last_accessed = datetime.now(timezone.utc)

            return session

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session by session_id.

        Args:
            session_id: Session identifier

        Returns:
            True if session was deleted, False if not found
        """
        with self._lock:
            session = self._sessions_by_id.get(session_id)

            if session is None:
                return False

            self._remove_session(session)
            return True

    def _remove_session(self, session: SessionData) -> None:
        """
        Remove session from both lookup dictionaries.

        Note: Must be called within a lock context.
        """
        self._sessions_by_id.pop(session.session_id, None)
        self._sessions_by_token.pop(session.token, None)

    def cleanup_expired_sessions(self) -> int:
        """
        Remove all expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        now = datetime.now(timezone.utc)
        expired_sessions = []

        with self._lock:
            # Find expired sessions
            for session in self._sessions_by_id.values():
                if session.is_expired(now):
                    expired_sessions.append(session)

            # Remove them
            for session in expired_sessions:
                self._remove_session(session)

        return len(expired_sessions)

    def get_session_count(self) -> int:
        """Get the current number of active sessions."""
        with self._lock:
            return len(self._sessions_by_id)


# Global session store instance
session_store = SessionStore()
