"""Tests for M3U8 manifest rewriter."""

import pytest

from app.m3u8_rewriter import M3U8Rewriter


class TestM3U8Rewriter:
    """Test suite for M3U8 manifest rewriting."""

    def test_rewrite_simple_media_playlist(self):
        """Test rewriting a simple media playlist with relative URLs."""
        token = "test_token_123"
        session_base_url = "https://cdn.example.com/content/2025"
        rewriter = M3U8Rewriter(token=token, session_base_url=session_base_url)

        manifest = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:1
#EXTINF:10.0,
segment001.ts
#EXTINF:10.0,
segment002.ts
#EXT-X-ENDLIST"""

        manifest_url = "https://cdn.example.com/content/2025/stream.m3u8"
        result = rewriter.rewrite_manifest(manifest, manifest_url)

        assert "/stream/segment001.ts?token=test_token_123" in result
        assert "/stream/segment002.ts?token=test_token_123" in result
        assert "#EXTM3U" in result
        assert "#EXT-X-ENDLIST" in result

    def test_rewrite_relative_paths_with_subdirs(self):
        """Test rewriting relative paths with subdirectories."""
        token = "test_token_456"
        session_base_url = "https://cdn.example.com/content/2025"
        rewriter = M3U8Rewriter(token=token, session_base_url=session_base_url)

        manifest = """#EXTM3U
#EXT-X-VERSION:3
#EXTINF:6.006,
video_stream_4000K/00000/segment_00001.ts
#EXTINF:6.006,
video_stream_4000K/00000/segment_00002.ts"""

        manifest_url = "https://cdn.example.com/content/2025/master.m3u8"
        result = rewriter.rewrite_manifest(manifest, manifest_url)

        assert "/stream/video_stream_4000K/00000/segment_00001.ts?token=test_token_456" in result
        assert "/stream/video_stream_4000K/00000/segment_00002.ts?token=test_token_456" in result

    def test_rewrite_master_playlist(self):
        """Test rewriting a master playlist with variant streams."""
        token = "test_token_789"
        session_base_url = "https://cdn.example.com/content"
        rewriter = M3U8Rewriter(token=token, session_base_url=session_base_url)

        manifest = """#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=2000000,RESOLUTION=1280x720
720p/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080
1080p/index.m3u8"""

        manifest_url = "https://cdn.example.com/content/master.m3u8"
        result = rewriter.rewrite_manifest(manifest, manifest_url)

        assert "/stream/720p/index.m3u8?token=test_token_789" in result
        assert "/stream/1080p/index.m3u8?token=test_token_789" in result

    def test_rewrite_absolute_urls(self):
        """Test rewriting absolute URLs."""
        token = "test_token_abs"
        session_base_url = "https://cdn.example.com/content/2025"
        rewriter = M3U8Rewriter(token=token, session_base_url=session_base_url)

        manifest = """#EXTM3U
#EXTINF:10.0,
https://cdn.example.com/content/2025/segment001.ts
#EXTINF:10.0,
https://cdn.example.com/content/2025/segment002.ts"""

        manifest_url = "https://cdn.example.com/content/2025/stream.m3u8"
        result = rewriter.rewrite_manifest(manifest, manifest_url)

        assert "/stream/segment001.ts?token=test_token_abs" in result
        assert "/stream/segment002.ts?token=test_token_abs" in result

    def test_rewrite_ext_x_key_uri(self):
        """Test rewriting #EXT-X-KEY URI attribute."""
        token = "test_token_key"
        session_base_url = "https://cdn.example.com"
        rewriter = M3U8Rewriter(token=token, session_base_url=session_base_url)

        manifest = """#EXTM3U
#EXT-X-KEY:METHOD=AES-128,URI="https://cdn.example.com/keys/key.bin"
#EXTINF:10.0,
segment001.ts"""

        manifest_url = "https://cdn.example.com/content/stream.m3u8"
        result = rewriter.rewrite_manifest(manifest, manifest_url)

        assert 'URI="/stream/keys/key.bin?token=test_token_key"' in result

    def test_preserve_comments_and_metadata(self):
        """Test that comment lines and metadata are preserved."""
        token = "test_token_preserve"
        session_base_url = "https://cdn.example.com"
        rewriter = M3U8Rewriter(token=token, session_base_url=session_base_url)

        manifest = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-PLAYLIST-TYPE:VOD
#EXTINF:10.0,
segment001.ts"""

        manifest_url = "https://cdn.example.com/stream.m3u8"
        result = rewriter.rewrite_manifest(manifest, manifest_url)

        assert "#EXTM3U" in result
        assert "#EXT-X-VERSION:3" in result
        assert "#EXT-X-TARGETDURATION:10" in result
        assert "#EXT-X-PLAYLIST-TYPE:VOD" in result

    def test_extract_path_from_proxy_url(self):
        """Test extracting original path from proxy URL."""
        # With leading slash
        assert (
            M3U8Rewriter.extract_path_from_proxy_url("/stream/path/to/file.m3u8")
            == "path/to/file.m3u8"
        )

        # Without leading slash
        assert (
            M3U8Rewriter.extract_path_from_proxy_url("stream/path/to/file.m3u8")
            == "path/to/file.m3u8"
        )

        # Edge case: no stream prefix
        assert M3U8Rewriter.extract_path_from_proxy_url("/path/to/file.m3u8") == "path/to/file.m3u8"

    def test_empty_lines_preserved(self):
        """Test that empty lines are preserved."""
        token = "test_token_empty"
        session_base_url = "https://cdn.example.com"
        rewriter = M3U8Rewriter(token=token, session_base_url=session_base_url)

        manifest = """#EXTM3U
#EXT-X-VERSION:3

#EXTINF:10.0,
segment001.ts

#EXT-X-ENDLIST"""

        manifest_url = "https://cdn.example.com/stream.m3u8"
        result = rewriter.rewrite_manifest(manifest, manifest_url)

        # Should preserve empty lines
        lines = result.splitlines()
        assert "" in lines
