"""Pytest fixtures and shared utilities for Strigoth tests."""

import warnings
import pytest
from datetime import datetime
from pathlib import Path

from core.models import LogEntry
from core.filter_engine import FilterEngine, FilterState
from core.stats import StatsEngine
from rules.security import SecurityRules, Alert

# Suppress coverage warnings
try:
    from coverage.exceptions import CoverageWarning
    warnings.filterwarnings("ignore", category=CoverageWarning)
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Sample Log Entry Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_log_entry():
    """Create a sample LogEntry for testing."""
    return LogEntry(
        ip="192.168.1.1",
        time=datetime(2026, 3, 24, 10, 15, 30),
        method="GET",
        path="/",
        status=200,
        size=5432,
        referer="-",
        agent="Mozilla/5.0",
        raw='192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0"',
        source_file="access.log",
        source_label="Server1"
    )


@pytest.fixture
def sample_entries():
    """Create a list of sample log entries for testing."""
    return [
        LogEntry(
            ip="192.168.1.1",
            time=datetime(2026, 3, 24, 10, 15, 30),
            method="GET",
            path="/",
            status=200,
            size=5432,
            referer="-",
            agent="Mozilla/5.0",
            raw='192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0"',
            source_file="access.log",
            source_label="Server1"
        ),
        LogEntry(
            ip="192.168.1.2",
            time=datetime(2026, 3, 24, 10, 15, 31),
            method="POST",
            path="/login",
            status=401,
            size=123,
            referer="-",
            agent="curl/7.68.0",
            raw='192.168.1.2 - - [24/Mar/2026:10:15:31 +0000] "POST /login HTTP/1.1" 401 123 "-" "curl/7.68.0"',
            source_file="access.log",
            source_label="Server1"
        ),
        LogEntry(
            ip="192.168.1.3",
            time=datetime(2026, 3, 24, 10, 15, 32),
            method="GET",
            path="/admin",
            status=403,
            size=456,
            referer="-",
            agent="Mozilla/5.0",
            raw='192.168.1.3 - - [24/Mar/2026:10:15:32 +0000] "GET /admin HTTP/1.1" 403 456 "-" "Mozilla/5.0"',
            source_file="access.log",
            source_label="Server1"
        ),
        LogEntry(
            ip="192.168.1.4",
            time=datetime(2026, 3, 24, 10, 15, 33),
            method="GET",
            path="/api/data",
            status=500,
            size=789,
            referer="-",
            agent="Mozilla/5.0",
            raw='192.168.1.4 - - [24/Mar/2026:10:15:33 +0000] "GET /api/data HTTP/1.1" 500 789 "-" "Mozilla/5.0"',
            source_file="access.log",
            source_label="Server1"
        ),
    ]


@pytest.fixture
def brute_force_entries():
    """Create entries simulating brute force attack."""
    entries = []
    for i in range(15):
        entries.append(
            LogEntry(
                ip="10.0.0.50",
                time=datetime(2026, 3, 24, 10, 15, i),
                method="POST",
                path="/login",
                status=401,
                size=123,
                referer="-",
                agent="curl/7.68.0",
                raw=f'10.0.0.50 - - [24/Mar/2026:10:15:{i:02d} +0000] "POST /login HTTP/1.1" 401 123 "-" "curl/7.68.0"',
                source_file="access.log",
                source_label="Server1"
            )
        )
    return entries


@pytest.fixture
def scanning_entries():
    """Create entries simulating scanning behavior."""
    entries = []
    paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git",
             "/config", "/backup", "/wp-config.php", "/xmlrpc.php", "/pma",
             "/.htaccess", "/manager", "/console", "/admin.php", "/test"]
    
    for i, path in enumerate(paths):
        entries.append(
            LogEntry(
                ip="172.16.0.200",
                time=datetime(2026, 3, 24, 10, 15, i),
                method="GET",
                path=path,
                status=404,
                size=234,
                referer="-",
                agent="Mozilla/5.0",
                raw=f'172.16.0.200 - - [24/Mar/2026:10:15:{i:02d} +0000] "GET {path} HTTP/1.1" 404 234 "-" "Mozilla/5.0"',
                source_file="access.log",
                source_label="Server1"
            )
        )
    return entries


# ─────────────────────────────────────────────────────────────────────────────
# Engine Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def filter_engine():
    """Create a FilterEngine instance for testing."""
    return FilterEngine()


@pytest.fixture
def stats_engine(sample_entries):
    """Create a StatsEngine instance with sample data."""
    engine = StatsEngine()
    engine.load(sample_entries)
    return engine


@pytest.fixture
def security_rules():
    """Create a SecurityRules instance for testing."""
    return SecurityRules()


# ─────────────────────────────────────────────────────────────────────────────
# Sample Data Files
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_log_file(tmp_path):
    """Create a temporary sample log file."""
    log_content = """192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0"
192.168.1.2 - - [24/Mar/2026:10:15:31 +0000] "POST /login HTTP/1.1" 401 123 "-" "curl/7.68.0"
192.168.1.3 - - [24/Mar/2026:10:15:32 +0000] "GET /admin HTTP/1.1" 403 456 "-" "Mozilla/5.0"
192.168.1.4 - - [24/Mar/2026:10:15:33 +0000] "GET /api/data HTTP/1.1" 500 789 "-" "Mozilla/5.0"
192.168.1.5 - - [24/Mar/2026:10:15:34 +0000] "GET /page HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
"""
    log_file = tmp_path / "test_access.log"
    log_file.write_text(log_content)
    return log_file


@pytest.fixture
def sample_apache_log_file(tmp_path):
    """Create a temporary Apache format log file."""
    log_content = """127.0.0.1 - frank [24/Mar/2026:10:15:30 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/" "Mozilla/4.08"
127.0.0.1 - - [24/Mar/2026:10:15:31 -0700] "GET /test HTTP/1.1" 404 123
"""
    log_file = tmp_path / "test_apache.log"
    log_file.write_text(log_content)
    return log_file
