"""Main FastAPI application for AirPlay-CloudFront HLS Proxy."""

import logging
import os
import asyncio
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncGenerator, Set

import httpx
from fastapi import FastAPI, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, StreamingResponse

from app.config import settings
from app.exceptions import (
    CloudFrontError,
    InvalidTokenError,
    PathTraversalError,
)
from app.m3u8_rewriter import M3U8Rewriter
from app.models import (
    CloudFrontCookies,
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


class WebSocketLogHandler(logging.Handler):
    """Custom logging handler that broadcasts logs to WebSocket connections."""
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record to all WebSocket connections."""
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": self.format(record),
            }
            # Add to buffer
            log_buffer.append(log_entry)
            # Broadcast to all WebSocket connections (non-blocking)
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._broadcast(log_entry))
                else:
                    loop.run_until_complete(self._broadcast(log_entry))
            except RuntimeError:
                # No event loop, skip broadcasting
                pass
        except Exception:
            pass  # Don't let logging errors break the app
    
    async def _broadcast(self, log_entry: dict) -> None:
        """Broadcast log entry to all connected WebSockets."""
        disconnected = set()
        for ws in websocket_connections:
            try:
                await ws.send_json(log_entry)
            except Exception:
                disconnected.add(ws)
        # Remove disconnected connections
        websocket_connections.difference_update(disconnected)


# Add WebSocket log handler
ws_handler = WebSocketLogHandler()
ws_handler.setLevel(logging.DEBUG)
logger.addHandler(ws_handler)

# Global HTTP client for CloudFront requests
http_client: httpx.AsyncClient | None = None

# Global demo session info
demo_session: SessionResponse | None = None

# WebSocket connections for log streaming
websocket_connections: Set[WebSocket] = set()

# In-memory log buffer (last 1000 log entries)
log_buffer: deque = deque(maxlen=1000)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifespan (startup and shutdown)."""
    global http_client, demo_session

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

    # Create demo session if enabled
    if settings.demo_stream_enabled:
        try:
            # Create demo session with fixed IDs that persist across deployments
            # Fixed IDs: s_demo_boops_and_bips and t_demo_boops_and_bips
            demo_cookies = CloudFrontCookies(
                CloudFront_Policy="demo",
                CloudFront_Signature="demo",
                CloudFront_Key_Pair_Id="demo",
            )
            
            demo_session_data = session_store.create_session(
                base_url=settings.demo_stream_base_url,
                cookies=demo_cookies,
                ttl=settings.session_max_ttl_seconds,  # Use max TTL for demo session
                session_id="s_demo_boops_and_bips",
                token="t_demo_boops_and_bips",
            )
            
            demo_session = SessionResponse(
                session_id=demo_session_data.session_id,
                token=demo_session_data.token,
                expires_at=demo_session_data.expires_at,
            )
            
            logger.info(
                f"Demo session created: session_id={demo_session.session_id}, "
                f"token={demo_session.token}, stream_url={settings.demo_stream_url}"
            )
        except Exception as e:
            logger.warning(f"Failed to create demo session: {e}")
            demo_session = None

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


@app.exception_handler(ExceptionGroup)
async def exception_group_handler(request: Request, exc: ExceptionGroup):
    """
    Handle ExceptionGroup exceptions that occur during streaming responses.
    
    These can happen when clients disconnect during streaming, causing
    StreamClosed exceptions to be wrapped in ExceptionGroup by Starlette's
    TaskGroup handling.
    Note: This handler only applies to HTTP requests, not WebSocket connections.
    """
    # Skip WebSocket connections - they have their own error handling
    if request.url.path.startswith("/ws/"):
        raise exc
    
    # Check if any exception in the group is a StreamClosed exception
    if any(isinstance(e, httpx.StreamClosed) for e in exc.exceptions):
        logger.debug(f"Stream closed by client (ExceptionGroup handler): {request.url.path}")
        # Suppress the exception - response may have already started
        # Starlette will handle cleanup for streaming responses
        return
    
    # Check for RuntimeError about response already started or Content-Length mismatch
    if any(
        "response already started" in str(e).lower() or 
        "response content shorter than content-length" in str(e).lower()
        for e in exc.exceptions
    ):
        logger.debug(
            f"Response error (already started or Content-Length mismatch), "
            f"suppressing ExceptionGroup: {request.url.path}"
        )
        # Suppress the exception - can't return new response when streaming has started
        # Content-Length mismatch happens when client disconnects early, which is normal for HLS
        return
    
    # If it's not a StreamClosed exception, log and re-raise
    logger.error(f"Unhandled ExceptionGroup: {exc}")
    raise exc


@app.exception_handler(RuntimeError)
async def runtime_error_handler(request: Request, exc: RuntimeError):
    """
    Handle RuntimeError exceptions, particularly "response already started" errors.
    
    These occur when exceptions happen during streaming after headers are sent.
    Note: This handler only applies to HTTP requests, not WebSocket connections.
    """
    # Skip WebSocket connections - they have their own error handling
    if request.url.path.startswith("/ws/"):
        raise exc
    
    error_msg_lower = str(exc).lower()
    if "response already started" in error_msg_lower or "response content shorter than content-length" in error_msg_lower:
        logger.debug(
            f"RuntimeError: Response error (already started or Content-Length mismatch), "
            f"suppressing: {request.url.path}"
        )
        # Suppress the exception - can't return new response when streaming has started
        # Content-Length mismatch happens when client disconnects early, which is normal for HLS
        return
    # Re-raise if it's not about response already started or Content-Length mismatch
    raise exc


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
        f"[PROXY] Request: path={path}, token={token[:8]}..., "
        f"cloudfront_url={cloudfront_url}, method={request.method}, "
        f"client_ip={request.client.host if request.client else 'unknown'}"
    )

    # Prepare cookies for CloudFront request (skip demo cookies)
    cookie_header = ""
    if session_data.cookies and not all(v == "demo" for v in session_data.cookies.values()):
        cookie_header = "; ".join(f"{k}={v}" for k, v in session_data.cookies.items())

    # Fetch from CloudFront
    try:
        # Build headers (only include Cookie if we have real cookies)
        headers = {
            "User-Agent": request.headers.get("User-Agent", "AirPlayProxy/1.0"),
        }
        if cookie_header:
            headers["Cookie"] = cookie_header
        
        # Forward Range header for byte-range requests (required for #EXT-X-BYTERANGE)
        if "Range" in request.headers:
            headers["Range"] = request.headers["Range"]
            logger.info(f"[PROXY] Forwarding Range header: {request.headers['Range']}")
        
        logger.info(f"[PROXY] Request headers: {list(headers.keys())}")
        
        logger.info(f"[PROXY] Fetching from CloudFront: {cloudfront_url}")
        async with http_client.stream(
            "GET",
            cloudfront_url,
            headers=headers,
        ) as cf_response:
            logger.info(
                f"[PROXY] CloudFront response: status={cf_response.status_code}, "
                f"headers={dict(cf_response.headers)}, path={path}"
            )
            
            # Check for CloudFront errors
            if cf_response.status_code >= 400:
                logger.error(
                    f"[PROXY] CloudFront error: status={cf_response.status_code}, "
                    f"url={cloudfront_url}, path={path}"
                )
                raise CloudFrontError(
                    status_code=cf_response.status_code,
                    detail=f"CloudFront returned {cf_response.status_code}",
                )

            # Determine content type
            content_type = cf_response.headers.get("Content-Type") or _get_content_type(path)
            logger.info(f"[PROXY] Content type: {content_type}, path={path}")

            # For M3U8 files, rewrite the manifest
            if path.endswith(".m3u8"):
                logger.info(f"[PROXY] Rewriting M3U8 manifest: {path}")

                # Read entire manifest (they're typically small)
                manifest_content = await cf_response.aread()
                manifest_size = len(manifest_content)
                logger.info(f"[PROXY] Manifest size: {manifest_size} bytes, path={path}")
                
                manifest_text = manifest_content.decode("utf-8")
                logger.debug(f"[PROXY] Manifest preview (first 200 chars): {manifest_text[:200]}")

                # Rewrite URLs in manifest (use absolute URLs for better browser compatibility)
                proxy_base_url = str(request.base_url).rstrip("/")
                rewriter = M3U8Rewriter(
                    token=token,
                    session_base_url=session_data.base_url,
                    proxy_base_url=proxy_base_url,
                )
                rewritten_manifest = rewriter.rewrite_manifest(
                    manifest_text,
                    base_url=cloudfront_url,
                )
                logger.info(f"[PROXY] Manifest rewritten: {len(rewritten_manifest)} bytes, path={path}")

                return Response(
                    content=rewritten_manifest,
                    media_type=content_type,
                    headers={
                        "Cache-Control": "no-cache",
                        "Access-Control-Allow-Origin": "*",
                        "X-Original-URL": cloudfront_url,  # Debug header showing original CloudFront URL
                    },
                )

            # Get the fetched size from CloudFront response
            fetched_size = cf_response.headers.get("Content-Length")
            if fetched_size:
                fetched_size = int(fetched_size)
            else:
                fetched_size = None

            # For non-M3U8 files (segments), buffer the content to avoid partial/chunk issues
            body = await cf_response.aread()
            bytes_fetched = len(body)
            logger.info(
                f"[PROXY] Buffered segment: path={path}, bytes={bytes_fetched}, "
                f"fetched_size_header={fetched_size}"
            )

            # Build response headers
            response_headers = {
                "Accept-Ranges": cf_response.headers.get("Accept-Ranges", "bytes"),
                "Cache-Control": cf_response.headers.get("Cache-Control", ""),
                "Access-Control-Allow-Origin": "*",
                "X-Original-URL": cloudfront_url,  # Debug header showing original CloudFront URL
                "Content-Length": str(bytes_fetched),
            }
            
            # Add fetched size header if available
            if fetched_size is not None:
                response_headers["X-Fetched-Size"] = str(fetched_size)
            
            # Forward Content-Range header for byte-range responses
            if "Content-Range" in cf_response.headers:
                response_headers["Content-Range"] = cf_response.headers["Content-Range"]
                logger.info(f"[PROXY] Forwarding Content-Range: {cf_response.headers['Content-Range']}, path={path}")
            
            # Set status code (206 for partial content if Range was requested)
            status_code = status.HTTP_206_PARTIAL_CONTENT if "Range" in request.headers else status.HTTP_200_OK
            logger.info(f"[PROXY] Response status: {status_code}, path={path}")
            
            return Response(
                content=body,
                media_type=content_type,
                status_code=status_code,
                headers=response_headers,
            )

    except httpx.StreamClosed:
        # Client disconnected during streaming - this is normal for HLS
        logger.debug(f"Stream closed by client during request: {path}")
        return Response(
            content="",
            status_code=status.HTTP_200_OK,
            headers={"Access-Control-Allow-Origin": "*"},
        )
    except ExceptionGroup as eg:
        # Handle ExceptionGroup (Python 3.11+) - check if it contains StreamClosed
        if any(isinstance(exc, httpx.StreamClosed) for exc in eg.exceptions):
            logger.debug(f"Stream closed by client (ExceptionGroup): {path}")
            return Response(
                content="",
                status_code=status.HTTP_200_OK,
                headers={"Access-Control-Allow-Origin": "*"},
            )
        # Re-raise if it's not a StreamClosed exception
        raise
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


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket endpoint for streaming logs to clients."""
    await websocket.accept()
    websocket_connections.add(websocket)
    logger.info(f"[WS] Client connected: {len(websocket_connections)} total connections")
    
    try:
        # Send buffered logs first
        for log_entry in log_buffer:
            try:
                await websocket.send_json(log_entry)
            except Exception:
                break
        
        # Keep connection alive - wait for client disconnect
        # Use receive() with timeout to detect disconnects without blocking
        while True:
            try:
                # Wait for any message (or disconnect) with timeout
                # If client sends ping, we'll receive it; if disconnect, exception is raised
                await asyncio.wait_for(websocket.receive(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.debug(f"[WS] Connection error: {e}")
                break
    except Exception as e:
        logger.debug(f"[WS] Connection error: {e}")
    finally:
        websocket_connections.discard(websocket)
        logger.info(f"[WS] Client disconnected: {len(websocket_connections)} remaining connections")


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
async def root(request: Request) -> HTMLResponse:
    """Root endpoint with HLS player page and demo stream info."""
    base_url = str(request.base_url).rstrip("/")
    
    response_data = {
        "service": "AirPlay-CloudFront HLS Proxy",
        "version": "0.1.0",
        "docs": "/docs",
    }
    
    stream_url = None
    demo_info = None
    
    # Add demo stream info if available
    if demo_session:
        # Extract the manifest path from the demo stream URL
        from urllib.parse import urlparse
        parsed_demo_url = urlparse(settings.demo_stream_url)
        parsed_base_url = urlparse(settings.demo_stream_base_url)
        
        # Get the path relative to base URL
        demo_path = parsed_demo_url.path
        base_path = parsed_base_url.path.rstrip("/")
        if demo_path.startswith(base_path):
            manifest_path = demo_path[len(base_path):].lstrip("/")
        else:
            # Fallback: use the filename from the demo URL
            manifest_path = demo_path.split("/")[-1] or "x36xhzz.m3u8"
        
        stream_url = f"{base_url}/stream/{manifest_path}?token={demo_session.token}"
        
        demo_info = {
            "enabled": True,
            "name": "boops and bips",
            "stream_url": stream_url,
            "session_id": demo_session.session_id,
            "token": demo_session.token,
            "expires_at": demo_session.expires_at.isoformat(),
            "original_url": settings.demo_stream_url,
        }
        response_data["demo_stream"] = demo_info
    else:
        response_data["demo_stream"] = {"enabled": False}
    
    # Load HTML template
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(template_path, "r") as f:
        html_template = f.read()
    
    # Build video player section
    import json
    json_str = json.dumps(response_data, indent=2)
    
    video_section = ""
    if stream_url and demo_info:
        video_section = f"""
            <div class="section">
                <h2>📺 Video Player</h2>
                <div class="video-container">
                    <video id="hls-player" controls preload="metadata">
                        <source src="{stream_url}" type="application/vnd.apple.mpegurl">
                        Your browser does not support the video tag or HLS playback.
                    </video>
                </div>
                <div class="info-box">
                    <p><strong>Stream:</strong> {demo_info['name']}</p>
                    <p><strong>Stream URL:</strong> <code>{stream_url}</code></p>
                    <p><strong>Session ID:</strong> <code>{demo_info['session_id']}</code></p>
                    <p><strong>Expires At:</strong> {demo_info['expires_at']}</p>
                </div>
            </div>
        """
    elif not stream_url:
        video_section = """
            <div class="section">
                <h2>📺 Video Player</h2>
                <div class="no-stream">
                    <p>Demo stream is not available. Please check the service configuration.</p>
                </div>
            </div>
        """
    
    # Replace template variables
    html_content = html_template.replace("{{video_section}}", video_section)
    html_content = html_content.replace("{{json_str}}", json_str)
    html_content = html_content.replace("{{stream_url}}", stream_url if stream_url else "")
    
    return HTMLResponse(content=html_content)
