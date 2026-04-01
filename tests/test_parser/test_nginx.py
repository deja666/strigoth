"""Tests for Nginx log parser."""

import pytest
from parser.nginx import parse_line


class TestNginxParser:
    """Test suite for Nginx log parser."""

    def test_parse_valid_line(self):
        """Test parsing a valid nginx log line."""
        line = '192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0"'
        entry = parse_line(line)
        
        assert entry is not None
        assert entry.ip == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.path == "/"
        assert entry.status == 200
        assert entry.size == 5432
        assert entry.agent == "Mozilla/5.0"

    def test_parse_post_request(self):
        """Test parsing POST request."""
        line = '192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "POST /login HTTP/1.1" 401 123 "-" "curl/7.68.0"'
        entry = parse_line(line)
        
        assert entry is not None
        assert entry.method == "POST"
        assert entry.path == "/login"
        assert entry.status == 401

    def test_parse_invalid_line(self):
        """Test parsing invalid log line returns None."""
        line = "This is not a valid log line"
        entry = parse_line(line)
        
        assert entry is None

    def test_parse_empty_line(self):
        """Test parsing empty line returns None."""
        line = ""
        entry = parse_line(line)
        
        assert entry is None

    def test_parse_malformed_line(self):
        """Test parsing malformed log line returns None."""
        line = '192.168.1.1 - - [invalid date] "GET / HTTP/1.1" 200 5432'
        entry = parse_line(line)
        
        assert entry is None

    def test_parse_all_http_methods(self):
        """Test parsing all HTTP methods."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        
        for method in methods:
            line = f'192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "{method} /api HTTP/1.1" 200 100 "-" "Test"'
            entry = parse_line(line)
            
            assert entry is not None
            assert entry.method == method

    def test_parse_all_status_ranges(self):
        """Test parsing different status code ranges."""
        test_cases = [
            (200, "Success"),
            (201, "Created"),
            (301, "Redirect"),
            (302, "Found"),
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (403, "Forbidden"),
            (404, "Not Found"),
            (500, "Internal Server Error"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
        ]
        
        for status, _ in test_cases:
            line = f'192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET / HTTP/1.1" {status} 100 "-" "Test"'
            entry = parse_line(line)
            
            assert entry is not None
            assert entry.status == status

    def test_parse_with_referer(self):
        """Test parsing line with referer."""
        line = '192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET /page HTTP/1.1" 200 100 "http://example.com/" "Mozilla/5.0"'
        entry = parse_line(line)
        
        assert entry is not None
        assert entry.referer == "http://example.com/"

    def test_parse_size_zero(self):
        """Test parsing line with zero size."""
        line = '192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET / HTTP/1.1" 204 0 "-" "Mozilla/5.0"'
        entry = parse_line(line)
        
        assert entry is not None
        assert entry.size == 0

    def test_parse_complex_path(self):
        """Test parsing line with complex path."""
        line = '192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET /api/v1/users?page=1&limit=10 HTTP/1.1" 200 1000 "-" "Mozilla/5.0"'
        entry = parse_line(line)
        
        assert entry is not None
        assert "/api/v1/users" in entry.path
