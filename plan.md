Architecture Overview
Problem: CloudFront uses signed cookies for HLS authentication, but AirPlay only accepts clean URLs without cookie support.
Solution: Create a proxy server that:

Accepts CloudFront cookies and creates a session
Provides cookieless URLs that embed session identifiers
Proxies all HLS requests (manifests + segments) to CloudFront with stored cookies
Rewrites manifest URLs to point back through the proxy

Core Components
1. Session Management Layer
Session Store with dual lookup:
├── session_id → session_data  # For management operations (refresh, delete)
├── token → session_data       # For streaming operations (fast lookup)
│
└── session_data: {
    ├── session_id: str
    ├── token: str  # Streaming authentication token
    ├── base_url: str  # CloudFront base URL (e.g., "https://cdn.example.com/content/2025")
    ├── cookies: Dict[str, str]  # CloudFront cookies
    ├── created_at: datetime
    ├── expires_at: datetime
    ├── last_accessed: datetime
    └── metadata: Optional[Dict]
}

**Multiple Feeds:** Single session/token supports all feeds under the same base_url
(e.g., different camera angles, audio tracks, quality levels all share one token)

Storage Options:
- Development: In-memory dict with threading.Lock
- Production: Redis for distributed sessions
- Hybrid: Redis with local LRU cache

2. Proxy Server

Framework: Flask or FastAPI
ASGI Server: uvicorn/gunicorn for production
HTTP Client: httpx (async support, connection pooling)

3. URL Rewriter

Parse M3U8 playlists (master + media)
Rewrite relative/absolute URLs to route through proxy
Preserve query parameters and fragments

API Endpoints

### POST /api/v1/session/create
Initialize streaming session with CloudFront cookies and the base URL. A single session supports multiple feeds (e.g., different camera angles, audio tracks).

**Request:**
```json
{
  "base_url": "https://cdn.example.com/content/2025",
  "cookies": {
    "CloudFront-Policy": "eyJTdGF0ZW1lbnQiOlt...",
    "CloudFront-Signature": "abc123...",
    "CloudFront-Key-Pair-Id": "APKAXXXXX"
  },
  "ttl": 3600  // optional, seconds
}
```

**Response:**
```json
{
  "session_id": "s_a1b2c3d4e5f6",
  "token": "t_x8y9z0a1b2c3d4e5",
  "expires_at": "2025-12-07T20:30:00Z"
}
```

**Usage Flow:**
1. Client app calls this endpoint with CloudFront cookies + base URL
2. Server creates session, stores base_url, generates `session_id` (for management) and `token` (for streaming)
3. Server returns `session_id`, `token`, and `expires_at`
4. Client constructs proxy URLs for each feed by replacing base URL with proxy server + `/stream/`, and appending token
   - Original feed 1: `https://cdn.example.com/content/2025/feed1_4000K.m3u8`
   - Original feed 2: `https://cdn.example.com/content/2025/feed2_4000K.m3u8`
   - Proxy feed 1: `https://proxy.render.com/stream/feed1_4000K.m3u8?token=t_x8y9z0a1b2c3d4e5`
   - Proxy feed 2: `https://proxy.render.com/stream/feed2_4000K.m3u8?token=t_x8y9z0a1b2c3d4e5`
5. Client app can pass any of the constructed proxy URLs to AirPlay device
6. AirPlay device makes all HLS requests through the proxy using the token (transparent CloudFront auth)
7. Single token works for all feeds under the same base URL
8. Token decouples authentication from the content path structure

### PUT /api/v1/session/{session_id}/refresh
Refresh the CloudFront cookies for an existing session (e.g., when cookies are about to expire).

**Request:**
```json
{
  "cookies": {
    "CloudFront-Policy": "eyJTdGF0ZW1lbnQiOlt...",
    "CloudFront-Signature": "new_signature...",
    "CloudFront-Key-Pair-Id": "APKAXXXXX"
  }
}
```

**Response:**
```json
{
  "session_id": "s_a1b2c3d4e5f6",
  "expires_at": "2025-12-07T21:30:00Z",
  "updated": true
}
```

**Note:** The token remains the same; only the CloudFront cookies are updated in the session.

### GET /stream/{path:path}?token={token}
Proxy HLS content (playlists and segments). This endpoint is called by the AirPlay device, not directly by the client app.

**Flow:**
1. Extract token from query parameter
2. Look up session by token and validate it exists and not expired
3. Reconstruct original CloudFront URL: `{base_url}/{captured_path}` where base_url is CloudFront base (e.g., `https://cdn.example.com/content/2025/feed1_4000K.m3u8`)
4. Fetch from CloudFront with stored cookies from the session
5. If M3U8: rewrite all URLs to include the token query parameter and `/stream/` prefix
6. Stream response to AirPlay device
7. Update last_accessed timestamp on the session

**Key Design Decisions:**
- Token is passed as a query parameter, decoupling authentication from the resource path
- Proxy URL structure mirrors CloudFront structure (just domain swap + /stream/ prefix + token)
- Client constructs proxy URL themselves - no need for server to return it

### DELETE /api/v1/session/{session_id}
Explicitly terminate session (optional, for cleanup)

### GET /health
Health check endpoint for Render
HLS-Specific Handling
Manifest Rewriting Logic

**Key Pattern:** Token-based authentication via query parameters

Master Playlist (master.m3u8):
```python
def rewrite_master_playlist(content: str, token: str, proxy_base: str) -> str:
    """
    Rewrite variant stream URLs and media playlist URLs

    Input:
    #EXTM3U
    #EXT-X-STREAM-INF:BANDWIDTH=2000000
    720p/index.m3u8

    Output:
    #EXTM3U
    #EXT-X-STREAM-INF:BANDWIDTH=2000000
    /stream/720p/index.m3u8?token=t_x8y9z0a1b2c3d4e5
    """
```

Media Playlist (variant.m3u8):
```python
def rewrite_media_playlist(content: str, token: str, proxy_base: str) -> str:
    """
    Rewrite segment URLs (.ts files)

    Input (relative URLs common in video streams):
    #EXTINF:6.00600
    video_stream_4000K/00000/segment_00001.ts

    Output:
    #EXTINF:6.00600
    /stream/video_stream_4000K/00000/segment_00001.ts?token=t_x8y9z0a1b2c3d4e5
    """
```

**Key Considerations:**
- Handle absolute URLs (convert to proxy path with token)
- Handle relative URLs (common in real streams - resolve against base, then proxy with token)
- Token stays constant across all URLs in the playlist
- Lines starting with `#` are tags (don't rewrite except `#EXT-X-KEY` URIs)
- Non-comment lines are resource URLs (rewrite these)
- Preserve #EXT-X-KEY encryption URLs (if present)
- Maintain byte-range requests for segments
- Support both VOD and Live streams

## Implementation Details

### **URL Path Resolution**
```
Original CloudFront structure:
https://d123.cloudfront.net/content/game123/master.m3u8
https://d123.cloudfront.net/content/game123/720p/index.m3u8
https://d123.cloudfront.net/content/game123/720p/segment001.ts

Proxied structure:
http://proxy.local/stream/{session_id}/master.m3u8
http://proxy.local/stream/{session_id}/720p/index.m3u8
http://proxy.local/stream/{session_id}/720p/segment001.ts

Mapping:
- Store base_url in session: "https://d123.cloudfront.net/content/game123"
- Reconstruct: base_url + "/" + captured_path
Cookie Forwarding
python# CloudFront typically uses 3 cookies for signed URLs:
required_cookies = [
    "CloudFront-Policy",
    "CloudFront-Signature", 
    "CloudFront-Key-Pair-Id"
]

# Attach to every proxied request
headers = {
    "Cookie": "; ".join(f"{k}={v}" for k, v in session.cookies.items())
}
Content-Type Preservation
pythoncontent_type_mapping = {
    ".m3u8": "application/vnd.apple.mpegurl",
    ".ts": "video/MP2T",
    ".m4s": "video/iso.segment",
    ".mp4": "video/mp4"
}
Security Considerations
Session Security

Session ID Generation: Use cryptographically secure random (secrets.token_urlsafe)
Session Expiration:

Default TTL: 1 hour
Max TTL: 6 hours (align with CloudFront cookie expiry)
Idle timeout: 30 minutes


Rate Limiting: Per session, max requests/second
IP Binding (optional): Tie session to client IP

Input Validation
python# Validate stream_url is from allowed domains
ALLOWED_DOMAINS = [
    "d123.cloudfront.net",  # Your CloudFront distribution
]

# Validate cookies have expected structure
def validate_cloudfront_cookies(cookies: dict) -> bool:
    required = {"CloudFront-Policy", "CloudFront-Signature", "CloudFront-Key-Pair-Id"}
    return required.issubset(cookies.keys())
Path Traversal Prevention
python# Prevent directory traversal attacks
def sanitize_path(path: str) -> str:
    # Remove ../ and ensure path stays within bounds
    normalized = os.path.normpath(path)
    if normalized.startswith(".."):
        raise ValueError("Invalid path")
    return normalized
Performance Optimizations
Connection Pooling
python# Reuse HTTP connections to CloudFront
http_client = httpx.AsyncClient(
    limits=httpx.Limits(
        max_keepalive_connections=20,
        max_connections=100
    ),
    timeout=httpx.Timeout(30.0)
)
Streaming Response
python# Don't buffer entire segments in memory
async def stream_segment(url: str, cookies: dict):
    async with http_client.stream("GET", url, cookies=cookies) as response:
        async for chunk in response.aiter_bytes(chunk_size=8192):
            yield chunk
Caching Strategy

Don't cache: Live stream manifests (constantly updating)
Cache briefly: VOD manifests (5-60 seconds)
Don't cache: Segments (waste of memory, single-use)
Cache: Session lookups (if using Redis, use local LRU)

Technology Stack Recommendation
Option 1: FastAPI (Recommended)
pythonPros:
+ Async/await native
+ Automatic OpenAPI docs
+ Type hints with Pydantic
+ High performance
+ Modern Python patterns

Stack:
- FastAPI
- uvicorn (ASGI server)
- httpx (async HTTP client)
- Redis (session store)
- Pydantic (validation)
Option 2: Flask
pythonPros:
+ Simpler, more familiar
+ Large ecosystem
+ Good for synchronous workloads

Stack:
- Flask
- gunicorn (WSGI server)
- requests (HTTP client)
- Redis (session store)
- marshmallow (validation)
```

## Deployment Architecture

### **Local Development**
```
iOS App → localhost:8000 → CloudFront
         ↓ AirPlay
      AppleTV → localhost:8000 → CloudFront
```

### **Production**
```
iOS App → Load Balancer → Proxy Service (multiple instances)
                              ↓
                           Redis Cluster
                              ↓
                          CloudFront
Scaling:

Stateless proxy instances (session in Redis)
Horizontal scaling with load balancer
Health checks on /health endpoint
Graceful shutdown (drain connections)

Error Handling Strategy
Failure Scenarios

Session expired/invalid: Return 401, client creates new session
CloudFront returns 403: Cookies invalid/expired, return 403 to client
Network timeout: Return 504, client retries
Manifest parse error: Return 502, log for debugging
CloudFront 404: Return 404, pass through

Logging Requirements
pythonLog per request:
- session_id
- requested_path
- cloudfront_status_code
- response_time_ms
- bytes_transferred
- client_ip
- user_agent (to identify AirPlay vs direct)
Testing Strategy
Unit Tests

Session creation/expiration
URL rewriting logic (master/media playlists)
Cookie validation
Path sanitization

Integration Tests

Full flow: create session → fetch master → fetch variant → fetch segment
CloudFront cookie forwarding
AirPlay compatibility (test with actual AppleTV if possible)
Session expiration and cleanup

Load Tests

Concurrent streams (simulate multiple AirPlay sessions)
Segment request rate (HLS generates many requests)
Memory usage under load

Monitoring & Observability
Key Metrics

Active sessions count
Request rate (per endpoint)
Latency percentiles (p50, p95, p99)
CloudFront error rate
Session creation/expiration rate
Bandwidth usage

Alerts

CloudFront 403 rate spike (cookie expiry issues)
High latency (> 2s for manifest, > 5s for segments)
Memory usage > 80%
Redis connection failures

Next Steps

Start with MVP: FastAPI + in-memory sessions + basic rewriting
Test with single stream: Verify AirPlay works end-to-end
Add Redis: For session persistence
Implement monitoring: Logging and metrics
Load test: Identify bottlenecks
Security hardening: Rate limiting, validation
Deploy: Containerize and deploy to your infrastructure

Would you like me to create the actual Python implementation for any of these components? I can start with a FastAPI-based MVP that includes session management and basic HLS proxying.
