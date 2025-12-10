"""Custom exceptions for the proxy server."""

from fastapi import HTTPException, status


class SessionNotFoundError(HTTPException):
    """Raised when a session is not found."""

    def __init__(self, session_identifier: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Session not found or expired: {session_identifier}",
        )


class SessionExpiredError(HTTPException):
    """Raised when a session has expired."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired",
        )


class InvalidTokenError(HTTPException):
    """Raised when an invalid token is provided."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
        )


class InvalidCookiesError(HTTPException):
    """Raised when CloudFront cookies are invalid."""

    def __init__(self, message: str = "Invalid CloudFront cookies"):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )


class InvalidDomainError(HTTPException):
    """Raised when base_url domain is not allowed."""

    def __init__(self, domain: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Domain not allowed: {domain}",
        )


class PathTraversalError(HTTPException):
    """Raised when path traversal is detected."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid path: directory traversal detected",
        )


class CloudFrontError(HTTPException):
    """Raised when CloudFront returns an error."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(
            status_code=status_code if status_code != 403 else status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


class M3U8ValidationError(HTTPException):
    """Raised when M3U8 validation fails during session creation."""

    def __init__(self, status_code: int, message: str):
        detail = f"M3U8 validation failed: {message}"
        if status_code == 403:
            detail += " (CloudFront cookies may be expired, invalid, or IP-restricted)"
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )
        self.cloudfront_status = status_code
