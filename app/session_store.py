"""Thread-safe in-memory session store."""

import secrets
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional
from urllib.parse import urlparse

from app.config import settings
from app.exceptions import InvalidDomainError, SessionExpiredError, SessionNotFoundError
from app.models import CloudFrontCookies, SessionData


@dataclass
class TrafficMetrics:
    """Traffic metrics for monitoring."""
    
    total_requests: int = 0
    m3u8_requests: int = 0
    ts_requests: int = 0
    other_requests: int = 0
    total_bytes: int = 0
    recent_traffic: deque = field(default_factory=lambda: deque(maxlen=100))
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _callbacks: list = field(default_factory=list)
    
    def record_request(
        self,
        path: str,
        method: str = "GET",
        status: int = 200,
        bytes_sent: int = 0,
        token: Optional[str] = None,
    ) -> dict:
        """Record a traffic request."""
        with self._lock:
            self.total_requests += 1
            self.total_bytes += bytes_sent
            
            if path.endswith(".m3u8"):
                self.m3u8_requests += 1
            elif path.endswith(".ts") or path.endswith(".m4s"):
                self.ts_requests += 1
            else:
                self.other_requests += 1
            
            entry = {
                "type": "traffic",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": path,
                "method": method,
                "status": status,
                "bytes": bytes_sent,
                "token": token[:8] + "..." if token and len(token) > 8 else token,
            }
            self.recent_traffic.append(entry)
            
            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(entry)
                except Exception:
                    pass
            
            return entry
    
    def add_callback(self, callback: Callable[[dict], None]) -> None:
        """Add a callback for traffic events."""
        with self._lock:
            self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[dict], None]) -> None:
        """Remove a traffic callback."""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
    
    def get_stats(self) -> dict:
        """Get current traffic statistics."""
        with self._lock:
            return {
                "type": "stats",
                "total_requests": self.total_requests,
                "m3u8_requests": self.m3u8_requests,
                "ts_requests": self.ts_requests,
                "other_requests": self.other_requests,
                "total_bytes": self.total_bytes,
            }
    
    def get_recent_traffic(self) -> list:
        """Get recent traffic entries."""
        with self._lock:
            return list(self.recent_traffic)
    
    def reset(self) -> dict:
        """Reset all traffic statistics and return cleared notification."""
        with self._lock:
            self.total_requests = 0
            self.m3u8_requests = 0
            self.ts_requests = 0
            self.other_requests = 0
            self.total_bytes = 0
            self.recent_traffic.clear()
            
            # Notify callbacks about reset
            entry = {
                "type": "reset",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": "Statistics cleared",
            }
            for callback in self._callbacks:
                try:
                    callback(entry)
                except Exception:
                    pass
            
            return entry


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
        session_id: Optional[str] = None,
        token: Optional[str] = None,
    ) -> SessionData:
        """
        Create a new session with CloudFront cookies.

        Args:
            base_url: CloudFront base URL (e.g., "https://cdn.example.com/content/2025")
            cookies: CloudFront signed cookies
            ttl: Optional session TTL in seconds (defaults to config value)
            session_id: Optional fixed session ID (for demo sessions)
            token: Optional fixed token (for demo sessions)

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

        # Generate IDs if not provided
        if session_id is None:
            session_id = self._generate_id("s")
        if token is None:
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

    def get_all_sessions(self) -> dict[str, dict]:
        """Get all active sessions as a dictionary for monitoring."""
        now = datetime.now(timezone.utc)
        with self._lock:
            sessions = {}
            for session_id, session in self._sessions_by_id.items():
                if not session.is_expired(now):
                    sessions[session_id] = {
                        "session_id": session.session_id,
                        "token": session.token[:8] + "..." if len(session.token) > 8 else session.token,
                        "base_url": session.base_url,
                        "created_at": session.created_at.isoformat(),
                        "expires_at": session.expires_at.isoformat(),
                        "last_accessed": session.last_accessed.isoformat(),
                    }
            return sessions


# Global session store instance
session_store = SessionStore()

# Global traffic metrics instance
traffic_metrics = TrafficMetrics()
