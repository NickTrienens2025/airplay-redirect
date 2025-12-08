"""HLS M3U8 manifest rewriter for token-based authentication."""

import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class M3U8Rewriter:
    """Rewrites M3U8 playlists to route URLs through the proxy with token authentication."""

    # Pattern to match URI attribute in #EXT-X-KEY tags
    URI_PATTERN = re.compile(r'URI="([^"]+)"')

    def __init__(self, token: str, session_base_url: str, proxy_base: str = "/stream"):
        """
        Initialize the rewriter.

        Args:
            token: Authentication token to append to URLs
            session_base_url: Session's CloudFront base URL (e.g., "https://cdn.example.com/content/2025")
            proxy_base: Base path for proxied requests (default: "/stream")
        """
        self.token = token
        self.session_base_url = session_base_url.rstrip("/")
        self.proxy_base = proxy_base.rstrip("/")

    def rewrite_manifest(self, content: str, base_url: str) -> str:
        """
        Rewrite all URLs in an M3U8 manifest to proxy through this server.

        Args:
            content: Original M3U8 manifest content
            base_url: Base URL for resolving relative URLs

        Returns:
            Rewritten M3U8 manifest with proxied URLs
        """
        lines = content.splitlines()
        rewritten_lines = []

        for line in lines:
            rewritten_line = self._rewrite_line(line, base_url)
            rewritten_lines.append(rewritten_line)

        return "\n".join(rewritten_lines)

    def _rewrite_line(self, line: str, base_url: str) -> str:
        """
        Rewrite a single line from the M3U8 manifest.

        Args:
            line: Original line from manifest
            base_url: Base URL for resolving relative URLs

        Returns:
            Rewritten line
        """
        line = line.rstrip()

        # Handle #EXT-X-KEY tags with URI attribute
        if line.startswith("#EXT-X-KEY:") and "URI=" in line:
            return self._rewrite_key_line(line, base_url)

        # Handle comment lines (keep as-is)
        if line.startswith("#") or not line.strip():
            return line

        # Handle URL lines (non-comment, non-empty lines are URLs)
        return self._rewrite_url(line, base_url)

    def _rewrite_key_line(self, line: str, base_url: str) -> str:
        """
        Rewrite #EXT-X-KEY line to proxy the encryption key URI.

        Args:
            line: Original #EXT-X-KEY line
            base_url: Base URL for resolving relative URLs

        Returns:
            Rewritten line with proxied URI
        """

        def replace_uri(match: re.Match) -> str:
            original_uri = match.group(1)
            proxied_uri = self._rewrite_url(original_uri, base_url)
            return f'URI="{proxied_uri}"'

        return self.URI_PATTERN.sub(replace_uri, line)

    def _rewrite_url(self, url: str, manifest_url: str) -> str:
        """
        Rewrite a URL to proxy through this server.

        Args:
            url: Original URL (can be relative or absolute)
            manifest_url: Full URL of the manifest being rewritten (for resolving relative URLs)

        Returns:
            Proxied URL with token parameter
        """
        # Strip whitespace
        url = url.strip()

        if not url:
            return url

        # Check if URL is absolute
        parsed = urlparse(url)
        is_absolute = bool(parsed.scheme and parsed.netloc)

        if is_absolute:
            # Absolute URL - extract just the path and query
            full_path = parsed.path
            existing_query = parse_qs(parsed.query)
        else:
            # Relative URL - resolve against manifest_url first
            absolute_url = urljoin(manifest_url, url)
            parsed_absolute = urlparse(absolute_url)
            full_path = parsed_absolute.path
            existing_query = parse_qs(parsed_absolute.query)

        # Strip the session base URL path from the full path
        # e.g., full_path="/content/2025/segment.ts", session_base="/content/2025" -> "segment.ts"
        session_base_parsed = urlparse(self.session_base_url)
        session_base_path = session_base_parsed.path.rstrip("/")

        if session_base_path and full_path.startswith(session_base_path + "/"):
            # Remove base path + slash
            relative_path = full_path[len(session_base_path) + 1 :]
        elif session_base_path and full_path.startswith(session_base_path):
            # Remove base path (no trailing slash case)
            relative_path = full_path[len(session_base_path) :].lstrip("/")
        else:
            # Path doesn't start with base path, use as-is
            relative_path = full_path.lstrip("/")

        # Build proxied path
        proxied_path = f"{self.proxy_base}/{relative_path}"

        # Add token to query parameters
        existing_query["token"] = [self.token]
        query_string = urlencode(existing_query, doseq=True)

        # Return proxied URL (relative path from proxy's perspective)
        if query_string:
            return f"{proxied_path}?{query_string}"
        return proxied_path

    @staticmethod
    def extract_path_from_proxy_url(proxy_path: str) -> str:
        """
        Extract the original path from a proxied URL path.

        Args:
            proxy_path: Path from proxy request (e.g., "/stream/path/to/file.m3u8")

        Returns:
            Original path relative to base_url (e.g., "path/to/file.m3u8")
        """
        # Remove /stream/ prefix
        if proxy_path.startswith("/stream/"):
            return proxy_path[8:]  # len("/stream/") = 8
        elif proxy_path.startswith("stream/"):
            return proxy_path[7:]  # len("stream/") = 7
        else:
            # Fallback: return as-is
            return proxy_path.lstrip("/")
