"""Main FastAPI application for AirPlay-CloudFront HLS Proxy."""

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, Query, Request, Response, status
from fastapi.responses import StreamingResponse

from app.config import settings
from app.exceptions import (
    CloudFrontError,
    InvalidTokenError,
    PathTraversalError,
)
from app.m3u8_rewriter import M3U8Rewriter
from app.models import (
    CreateSessionRequest,
    RefreshSessionRequest,
    RefreshSessionResponse,
    SessionResponse,
)
from app.session_store import session_store

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global HTTP client for CloudFront requests
http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifespan (startup and shutdown)."""
    global http_client

    # Startup
    logger.info("Starting AirPlay-CloudFront HLS Proxy")
    http_client = httpx.AsyncClient(
        limits=httpx.Limits(
            max_keepalive_connections=settings.http_max_keepalive_connections,
            max_connections=settings.http_max_connections,
        ),
        timeout=httpx.Timeout(settings.http_timeout_seconds),
        follow_redirects=True,
    )
    logger.info(f"HTTP client initialized with timeout={settings.http_timeout_seconds}s")

    yield

    # Shutdown
    logger.info("Shutting down AirPlay-CloudFront HLS Proxy")
    if http_client:
        await http_client.aclose()
        logger.info("HTTP client closed")


# Initialize FastAPI app
app = FastAPI(
    title="AirPlay-CloudFront HLS Proxy",
    description="Proxy server for streaming CloudFront-protected HLS content to AirPlay devices",
    version="0.1.0",
    lifespan=lifespan,
)


def _validate_path(path: str) -> None:
    """
    Validate path to prevent directory traversal attacks.

    Args:
        path: Path to validate

    Raises:
        PathTraversalError: If path contains directory traversal patterns
    """
    # Normalize path
    normalized = os.path.normpath(path)

    # Check for directory traversal
    if normalized.startswith("..") or "/../" in path:
        logger.warning(f"Path traversal attempt detected: {path}")
        raise PathTraversalError()


def _get_content_type(path: str) -> str:
    """
    Determine Content-Type based on file extension.

    Args:
        path: File path

    Returns:
        Appropriate Content-Type header value
    """
    path_lower = path.lower()

    if path_lower.endswith(".m3u8"):
        return "application/vnd.apple.mpegurl"
    elif path_lower.endswith(".ts"):
        return "video/MP2T"
    elif path_lower.endswith(".m4s"):
        return "video/iso.segment"
    elif path_lower.endswith(".mp4"):
        return "video/mp4"
    else:
        return "application/octet-stream"


@app.post(
    "/api/v1/session/create",
    response_model=SessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create streaming session",
    description="Initialize a new streaming session with CloudFront cookies",
)
async def create_session(request: CreateSessionRequest) -> SessionResponse:
    """
    Create a new streaming session.

    A single session can be used for multiple feeds from the same base URL.
    """
    logger.info(f"Creating session for base_url: {request.base_url}")

    session_data = session_store.create_session(
        base_url=str(request.base_url),
        cookies=request.cookies,
        ttl=request.ttl,
    )

    logger.info(
        f"Session created: session_id={session_data.session_id}, "
        f"expires_at={session_data.expires_at.isoformat()}"
    )

    return SessionResponse(
        session_id=session_data.session_id,
        token=session_data.token,
        expires_at=session_data.expires_at,
    )


@app.put(
    "/api/v1/session/{session_id}/refresh",
    response_model=RefreshSessionResponse,
    summary="Refresh session cookies",
    description="Update CloudFront cookies for an existing session",
)
async def refresh_session(
    session_id: str,
    request: RefreshSessionRequest,
) -> RefreshSessionResponse:
    """Refresh the CloudFront cookies for an existing session."""
    logger.info(f"Refreshing session: {session_id}")

    session_data = session_store.refresh_session_cookies(
        session_id=session_id,
        new_cookies=request.cookies,
    )

    logger.info(f"Session refreshed: {session_id}")

    return RefreshSessionResponse(
        session_id=session_data.session_id,
        expires_at=session_data.expires_at,
        updated=True,
    )


@app.delete(
    "/api/v1/session/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete session",
    description="Explicitly terminate a streaming session",
)
async def delete_session(session_id: str) -> None:
    """Delete a session explicitly."""
    logger.info(f"Deleting session: {session_id}")

    deleted = session_store.delete_session(session_id)

    if deleted:
        logger.info(f"Session deleted: {session_id}")
    else:
        logger.warning(f"Session not found for deletion: {session_id}")


@app.get(
    "/stream/{path:path}",
    summary="Stream HLS content",
    description="Proxy HLS content (playlists and segments) from CloudFront",
)
async def stream_content(
    request: Request,
    path: str,
    token: str = Query(..., description="Authentication token"),
) -> Response:
    """
    Proxy HLS content from CloudFront to the client (AirPlay device).

    This endpoint:
    1. Validates the token and retrieves the session
    2. Reconstructs the original CloudFront URL
    3. Fetches content from CloudFront with stored cookies
    4. For M3U8 files: rewrites URLs to include token and proxy through this server
    5. Streams the response to the client
    """
    # Validate token
    if not token:
        raise InvalidTokenError()

    # Validate path (prevent directory traversal)
    _validate_path(path)

    # Get session by token
    session_data = session_store.get_session_by_token(token)

    # Reconstruct original CloudFront URL
    # base_url (e.g., "https://cdn.example.com/content/2025") + "/" + path
    cloudfront_url = f"{session_data.base_url}/{path}"

    logger.info(
        f"Proxying request: token={token[:8]}..., path={path}, " f"cloudfront_url={cloudfront_url}"
    )

    # Prepare cookies for CloudFront request
    cookie_header = "; ".join(f"{k}={v}" for k, v in session_data.cookies.items())

    # Fetch from CloudFront
    try:
        async with http_client.stream(
            "GET",
            cloudfront_url,
            headers={
                "Cookie": cookie_header,
                "User-Agent": request.headers.get("User-Agent", "AirPlayProxy/1.0"),
            },
        ) as cf_response:
            # Check for CloudFront errors
            if cf_response.status_code >= 400:
                logger.error(
                    f"CloudFront error: status={cf_response.status_code}, " f"url={cloudfront_url}"
                )
                raise CloudFrontError(
                    status_code=cf_response.status_code,
                    detail=f"CloudFront returned {cf_response.status_code}",
                )

            # Determine content type
            content_type = cf_response.headers.get("Content-Type") or _get_content_type(path)

            # For M3U8 files, rewrite the manifest
            if path.endswith(".m3u8"):
                logger.debug(f"Rewriting M3U8 manifest: {path}")

                # Read entire manifest (they're typically small)
                manifest_content = await cf_response.aread()
                manifest_text = manifest_content.decode("utf-8")

                # Rewrite URLs in manifest
                rewriter = M3U8Rewriter(token=token, session_base_url=session_data.base_url)
                rewritten_manifest = rewriter.rewrite_manifest(
                    manifest_text,
                    base_url=cloudfront_url,
                )

                return Response(
                    content=rewritten_manifest,
                    media_type=content_type,
                    headers={
                        "Cache-Control": "no-cache",
                        "Access-Control-Allow-Origin": "*",
                    },
                )

            # For non-M3U8 files (segments), stream directly
            async def stream_generator() -> AsyncGenerator[bytes, None]:
                """Stream content in chunks."""
                async for chunk in cf_response.aiter_bytes(chunk_size=8192):
                    yield chunk

            return StreamingResponse(
                stream_generator(),
                media_type=content_type,
                headers={
                    "Content-Length": cf_response.headers.get("Content-Length", ""),
                    "Accept-Ranges": cf_response.headers.get("Accept-Ranges", "bytes"),
                    "Cache-Control": cf_response.headers.get("Cache-Control", ""),
                    "Access-Control-Allow-Origin": "*",
                },
            )

    except httpx.TimeoutException as e:
        logger.error(f"Timeout fetching from CloudFront: {cloudfront_url}")
        return Response(
            content="Gateway timeout",
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        )
    except httpx.HTTPError as e:
        logger.error(f"HTTP error fetching from CloudFront: {e}")
        return Response(
            content="Bad gateway",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


@app.get(
    "/health",
    summary="Health check",
    description="Health check endpoint for Render",
)
async def health_check() -> dict:
    """Health check endpoint."""
    session_count = session_store.get_session_count()

    return {
        "status": "healthy",
        "sessions": session_count,
        "version": "0.1.0",
    }


@app.get("/", include_in_schema=False)
async def root() -> dict:
    """Root endpoint with basic info."""
    return {
        "service": "AirPlay-CloudFront HLS Proxy",
        "version": "0.1.0",
        "docs": "/docs",
    }
