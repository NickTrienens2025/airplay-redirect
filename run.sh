#!/bin/bash
# Development server startup script

set -e

echo "Starting AirPlay-CloudFront HLS Proxy (Development Mode)"
echo "=========================================="

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run uvicorn with reload for development
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --log-level info
