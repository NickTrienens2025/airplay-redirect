# Quick Start Guide

## Running Locally

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start server
./run.sh

# Server will be running at http://localhost:8000
# API docs available at http://localhost:8000/docs
```

## Example Usage

### 1. Create a Session

```bash
curl -X POST http://localhost:8000/api/v1/session/create \
  -H "Content-Type: application/json" \
  -d '{
    "base_url": "https://cdn.example.com/content/2025",
    "cookies": {
      "CloudFront-Policy": "your_policy_value",
      "CloudFront-Signature": "your_signature_value",
      "CloudFront-Key-Pair-Id": "your_key_pair_id"
    }
  }'
```

Response:
```json
{
  "session_id": "s_abc123...",
  "token": "t_xyz789...",
  "expires_at": "2025-12-08T08:00:00Z"
}
```

### 2. Construct Proxy URLs

With the token from step 1, construct proxy URLs for your feeds:

```
Original: https://cdn.example.com/content/2025/feed1.m3u8
Proxied:  http://localhost:8000/stream/feed1.m3u8?token=t_xyz789...

Original: https://cdn.example.com/content/2025/feed2.m3u8
Proxied:  http://localhost:8000/stream/feed2.m3u8?token=t_xyz789...
```

### 3. Pass to AirPlay

Send the proxied URL to your AirPlay device. The device will automatically fetch:
- Master playlist (if applicable)
- Variant playlists
- All .ts segments

All requests will be authenticated via the token and proxied to CloudFront with your cookies.

### 4. Refresh Cookies (Optional)

If your CloudFront cookies are about to expire:

```bash
curl -X PUT http://localhost:8000/api/v1/session/s_abc123.../refresh \
  -H "Content-Type: application/json" \
  -d '{
    "cookies": {
      "CloudFront-Policy": "new_policy_value",
      "CloudFront-Signature": "new_signature_value",
      "CloudFront-Key-Pair-Id": "your_key_pair_id"
    }
  }'
```

### 5. Delete Session (Optional)

```bash
curl -X DELETE http://localhost:8000/api/v1/session/s_abc123...
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html
```

## Docker

```bash
# Build image
docker build -t airplay-proxy .

# Run container
docker run -p 8000:8000 airplay-proxy
```

## Deployment to Render

1. Push code to GitHub
2. Create new Web Service in Render
3. Connect your GitHub repository
4. Render will automatically detect the Dockerfile
5. Set environment variables in Render dashboard:
   - `ALLOWED_CLOUDFRONT_DOMAINS` (optional, comma-separated)
   - `LOG_LEVEL` (optional, default: info)

Render will automatically deploy on pushes to main branch.
