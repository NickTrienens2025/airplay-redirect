# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AirPlay-CloudFront HLS Proxy Server** - A proxy service that enables AirPlay streaming of HLS content protected by CloudFront signed cookies.

**Problem**: CloudFront uses signed cookies for HLS authentication, but AirPlay only accepts clean URLs without cookie support.

**Solution**: A proxy server that accepts CloudFront cookies to create sessions, provides cookieless URLs with embedded session identifiers, and proxies all HLS requests (manifests + segments) to CloudFront with stored cookies.

## Architecture

### Core Components

1. **Session Management Layer**
   - Session store with two mappings:
     - `session_id` → session data (for management/refresh operations)
     - `token` → session data (for streaming requests)
   - Session data contains: CloudFront cookies, CloudFront base URL, timestamps, and metadata
   - For MVP: In-memory storage with threading.Lock
   - Both session IDs and tokens must be cryptographically secure (use `secrets.token_urlsafe`)
   - Store the CloudFront base URL (e.g., `https://cdn.example.com/content/2025`), not individual feed URLs
   - Single session/token supports multiple feeds from the same base URL

2. **Proxy Server**
   - Recommended: FastAPI with uvicorn (async support)
   - Alternative: Flask with gunicorn
   - HTTP client: httpx for async requests with connection pooling

3. **URL Rewriter**
   - Parse M3U8 playlists (both master and media playlists)
   - Rewrite all URLs (relative and absolute) to route through proxy
   - Preserve query parameters, fragments, and encryption keys

### API Endpoints

#### `POST /api/v1/session/create`
Initialize a streaming session with CloudFront cookies. The session supports multiple feeds (e.g., different camera angles, audio tracks) from the same CloudFront domain.

**Request Body:**
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

**Client constructs proxy URLs for each feed:**
The client constructs proxy URLs by replacing the base URL with the proxy server and adding the token. A single session/token can be used for multiple feeds:
- Original feed 1: `https://cdn.example.com/content/2025/feed1.m3u8`
- Original feed 2: `https://cdn.example.com/content/2025/feed2.m3u8`
- Original feed 3: `https://cdn.example.com/content/2025/feed3.m3u8`

Becomes:
- Proxy feed 1: `https://proxy.render.com/stream/feed1.m3u8?token=t_x8y9z0a1b2c3d4e5`
- Proxy feed 2: `https://proxy.render.com/stream/feed2.m3u8?token=t_x8y9z0a1b2c3d4e5`
- Proxy feed 3: `https://proxy.render.com/stream/feed3.m3u8?token=t_x8y9z0a1b2c3d4e5`

All feeds share the same token and CloudFront cookies. The AirPlay device can switch between feeds seamlessly.

#### `PUT /api/v1/session/{session_id}/refresh`
Refresh the CloudFront cookies for an existing session (e.g., when cookies are about to expire).

**Request Body:**
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

Note: The token remains the same; only the cookies are updated.

#### `GET /stream/{path:path}?token={token}`
Proxy HLS content (playlists and segments). This endpoint is called by the AirPlay device, not directly by the client app.

**Flow:**
1. Extract token from query parameter
2. Look up session by token and validate it exists and hasn't expired
3. Reconstruct original CloudFront URL: `{base_url}/{captured_path}` (e.g., `https://cdn.example.com/content/2025` + `/` + `feed1_4000K.m3u8`)
4. Fetch from CloudFront with stored cookies from the session
5. If response is M3U8: rewrite all URLs to include the token query parameter and `/stream/` prefix
6. Stream response to AirPlay device
7. Update last_accessed timestamp on the session

#### `DELETE /api/v1/session/{session_id}`
Explicitly terminate session (optional cleanup).

#### `GET /health`
Health check endpoint for Render.

### URL Structure Mapping

```
Original CloudFront:
https://cdn.example.com/content/2025/feed1_4000K.m3u8
https://cdn.example.com/content/2025/feed1_4000K/720p/index.m3u8
https://cdn.example.com/content/2025/feed1_4000K/720p/segment001.ts

Proxied structure (token-based auth):
https://proxy.render.com/stream/feed1_4000K.m3u8?token=t_x8y9z0a1b2c3d4e5
https://proxy.render.com/stream/feed1_4000K/720p/index.m3u8?token=t_x8y9z0a1b2c3d4e5
https://proxy.render.com/stream/feed1_4000K/720p/segment001.ts?token=t_x8y9z0a1b2c3d4e5
```

The proxy URL mirrors the CloudFront URL structure with:
- CloudFront base URL replaced with proxy domain + `/stream/`
- Token query parameter appended
- Path after base URL is preserved

The server stores the CloudFront base URL (e.g., `https://cdn.example.com/content/2025`) and reconstructs original URLs by: `base_url + "/" + (path after /stream/)`. The token is used as the lookup key for the session.

**Multiple Feeds:** A single session/token can proxy multiple feeds from the same CloudFront base URL, allowing seamless switching between camera angles, audio tracks, etc.

## HLS-Specific Requirements

### Manifest Rewriting

- **Master playlists**: Rewrite variant stream URLs and media playlist references to include `?token=...`
- **Media playlists**: Rewrite segment URLs (.ts files) to include `?token=...`
- Handle both absolute and relative URLs (relative paths are common, e.g., `path/to/segment001.ts`)
- Preserve `#EXT-X-KEY` encryption URLs if present (add token parameter)
- Maintain byte-range request support for segments
- Support both VOD (`#EXT-X-PLAYLIST-TYPE:VOD` with `#EXT-X-ENDLIST`) and Live streams
- All rewritten URLs must include the token query parameter for authentication

**Example media playlist transformation:**
```
# Original line in m3u8:
video_stream_4000K/00000/segment_00001.ts

# Rewritten line:
/stream/video_stream_4000K/00000/segment_00001.ts?token=t_x8y9z0a1b2c3d4e5
```

Key implementation notes:
- Parse each line of the m3u8 file
- Lines starting with `#` are tags/metadata (don't rewrite, except `#EXT-X-KEY` URIs)
- Non-comment lines without `#` are URLs (rewrite these)
- Resolve relative URLs against the base URL before proxying
- Add token parameter to all resource URLs

### CloudFront Cookie Handling

CloudFront requires 3 cookies for signed URLs:
- `CloudFront-Policy`
- `CloudFront-Signature`
- `CloudFront-Key-Pair-Id`

These must be attached to every proxied request to CloudFront.

### Content-Type Preservation

- `.m3u8` → `application/vnd.apple.mpegurl`
- `.ts` → `video/MP2T`
- `.m4s` → `video/iso.segment`
- `.mp4` → `video/mp4`

## Security Requirements

### Session Security
- Session TTL: Default 1 hour, max 6 hours (align with CloudFront cookie expiry)
- Idle timeout: 30 minutes
- Rate limiting per session
- Optional: IP binding to tie session to client IP

### Input Validation
- Validate `stream_url` against allowed CloudFront domains
- Validate CloudFront cookies have expected structure
- Sanitize paths to prevent directory traversal (block `../` patterns)

### Allowed Domains
Maintain an allowlist of CloudFront distribution domains in configuration.

## Performance Considerations

### Connection Pooling
Configure httpx with:
- `max_keepalive_connections=20`
- `max_connections=100`
- `timeout=30.0`

### Streaming Response
Stream segments in chunks (8KB recommended) rather than buffering entire files in memory.

### Caching Strategy
- **Don't cache**: Live stream manifests (constantly updating), segments (single-use)
- **Cache briefly**: VOD manifests (5-60 seconds)
- **Cache**: Session lookups with local dict/LRU

## Error Handling

Map CloudFront responses to appropriate client responses:
- Session expired/invalid → 401
- CloudFront 403 (invalid/expired cookies) → 403
- Network timeout → 504
- Manifest parse error → 502
- CloudFront 404 → 404 (pass through)

## Logging

Log per request:
- `session_id`
- `requested_path`
- `cloudfront_status_code`
- `response_time_ms`
- `bytes_transferred`
- `client_ip`
- `user_agent` (to identify AirPlay vs direct)

## Testing Requirements

- **Unit tests**: Session management, URL rewriting logic, cookie validation, path sanitization
- **Integration tests**: Full flow from session creation through segment fetching, CloudFront cookie forwarding, AirPlay compatibility

## Technology Stack (Recommended)

**FastAPI Stack:**
- FastAPI (web framework)
- uvicorn (ASGI server)
- httpx (async HTTP client)
- Pydantic (validation)

## Deployment

This service is deployed to **Render** via CI/CD pipelines.

### Docker
- Use **Docker** for containerization (not docker-compose)
- Single Dockerfile for the application
- Render will build and deploy from the Dockerfile

### Render Configuration
- Service will be deployed as a web service on Render
- Use `uvicorn` as the production server
- Health checks should target the `/health` endpoint
- In-memory session storage is suitable for single-instance deployments

### CI/CD Pipeline
- Automated deployments trigger on pushes to main branch
- Render will auto-deploy based on repository updates
- Ensure environment variables are configured in Render dashboard (e.g., allowed CloudFront domains)
