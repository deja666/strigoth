"""Tests for Apache log parser."""

import pytest
from parser.apache import parse_line


class TestApacheParser:
    """Test suite for Apache log parser."""

    def test_parse_combined_format(self):
        """Test parsing Apache Combined Log Format."""
        line = '127.0.0.1 - frank [24/Mar/2026:10:15:30 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/" "Mozilla/4.08"'
        entry = parse_line(line)
        
        assert entry is not None
        assert entry.ip == "127.0.0.1"
        assert entry.method == "GET"
        assert entry.path == "/apache_pb.gif"
        assert entry.status == 200
        assert entry.size == 2326
        assert entry.referer == "http://www.example.com/"
        assert entry.agent == "Mozilla/4.08"

    def test_parse_common_format(self):
        """Test parsing Apache Common Log Format."""
        line = '127.0.0.1 - - [24/Mar/2026:10:15:30 -0700] "GET /test HTTP/1.1" 404 123'
        entry = parse_line(line)
        
        assert entry is not None
        assert entry.ip == "127.0.0.1"
        assert entry.method == "GET"
        assert entry.path == "/test"
        assert entry.status == 404
        assert entry.size == 123
        assert entry.referer == "-"
        assert entry.agent == ""

    def test_parse_invalid_line(self):
        """Test parsing invalid line returns None."""
        line = "This is not a valid Apache log line"
        entry = parse_line(line)
        
        assert entry is None

    def test_parse_empty_line(self):
        """Test parsing empty line returns None."""
        line = ""
        entry = parse_line(line)
        
        assert entry is None

    def test_parse_with_dash_size(self):
        """Test parsing line with dash as size."""
        line = '127.0.0.1 - - [24/Mar/2026:10:15:30 -0700] "GET /test HTTP/1.1" 204 -'
        entry = parse_line(line)
        
        assert entry is not None
        assert entry.size == 0

    def test_parse_all_status_codes(self):
        """Test parsing various status codes."""
        test_cases = [200, 201, 301, 302, 400, 401, 403, 404, 500, 502, 503]
        
        for status in test_cases:
            line = f'127.0.0.1 - - [24/Mar/2026:10:15:30 -0700] "GET / HTTP/1.1" {status} 100'
            entry = parse_line(line)
            
            assert entry is not None
            assert entry.status == status
