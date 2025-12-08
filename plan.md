Architecture Overview
Problem: CloudFront uses signed cookies for HLS authentication, but AirPlay only accepts clean URLs without cookie support.
Solution: Create a proxy server that:

Accepts CloudFront cookies and creates a session
Provides cookieless URLs that embed session identifiers
Proxies all HLS requests (manifests + segments) to CloudFront with stored cookies
Rewrites manifest URLs to point back through the proxy

Core Components
1. Session Management Layer
Session Store:
├── session_id → {
│   ├── cookies: Dict[str, str]  # CloudFront cookies
│   ├── created_at: datetime
│   ├── expires_at: datetime
│   ├── last_accessed: datetime
│   └── metadata: Optional[Dict]
}
Storage Options:

Development: In-memory dict with threading.Lock
Production: Redis for distributed sessions
Hybrid: Redis with local LRU cache

2. Proxy Server

Framework: Flask or FastAPI
ASGI Server: uvicorn/gunicorn for production
HTTP Client: httpx (async support, connection pooling)

3. URL Rewriter

Parse M3U8 playlists (master + media)
Rewrite relative/absolute URLs to route through proxy
Preserve query parameters and fragments

API Endpoints
POST /api/v1/session/create
Initialize streaming session with CloudFront cookies
Request:
json{
  "stream_url": "https://d123.cloudfront.net/path/master.m3u8",
  "cookies": {
    "CloudFront-Policy": "eyJTdGF0ZW1lbnQiOlt...",
    "CloudFront-Signature": "abc123...",
    "CloudFront-Key-Pair-Id": "APKAXXXXX"
  },
  "ttl": 3600  // optional, seconds
}
Response:
json{
  "session_id": "s_a1b2c3d4e5f6",
  "proxy_url": "http://proxy.local/stream/s_a1b2c3d4e5f6/master.m3u8",
  "expires_at": "2025-12-07T20:30:00Z"
}
GET /stream/{session_id}/{path:path}
Proxy HLS content (playlists and segments)
Flow:

Extract session_id from path
Validate session exists and not expired
Reconstruct original CloudFront URL
Fetch from CloudFront with stored cookies
If M3U8: rewrite URLs to include session_id
Stream response to client
Update last_accessed timestamp

DELETE /api/v1/session/{session_id}
Explicitly terminate session (optional, for cleanup)
GET /health
Health check endpoint
HLS-Specific Handling
Manifest Rewriting Logic
Master Playlist (master.m3u8):
pythondef rewrite_master_playlist(content: str, session_id: str, base_url: str) -> str:
    """
    Rewrite variant stream URLs and media playlist URLs
    
    Input:
    #EXTM3U
    #EXT-X-STREAM-INF:BANDWIDTH=2000000
    720p/index.m3u8
    
    Output:
    #EXTM3U
    #EXT-X-STREAM-INF:BANDWIDTH=2000000
    http://proxy.local/stream/{session_id}/720p/index.m3u8
    """
Media Playlist (variant.m3u8):
pythondef rewrite_media_playlist(content: str, session_id: str, base_url: str) -> str:
    """
    Rewrite segment URLs (.ts files)
    
    Input:
    #EXTINF:10.0
    segment001.ts
    
    Output:
    #EXTINF:10.0
    http://proxy.local/stream/{session_id}/720p/segment001.ts
    """
```

**Key Considerations:**
- Handle absolute URLs (convert to proxy path)
- Handle relative URLs (resolve against base, then proxy)
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
