"""Tests for Filter Engine."""

import pytest
from core.filter_engine import FilterEngine, FilterState
from core.models import LogEntry
from datetime import datetime


class TestFilterEngine:
    """Test suite for Filter Engine."""

    def test_no_filters_active(self, filter_engine):
        """Test that no filters are active initially."""
        assert not filter_engine.is_active()

    def test_filter_by_status(self, sample_entries, filter_engine):
        """Test filtering by status code."""
        filter_engine.set_filter("status", 200)
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 1
        assert filtered[0].status == 200

    def test_filter_by_status_not_found(self, sample_entries, filter_engine):
        """Test filtering by non-existent status code."""
        filter_engine.set_filter("status", 999)
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 0

    def test_filter_by_ip(self, sample_entries, filter_engine):
        """Test filtering by IP address (substring match)."""
        filter_engine.set_filter("ip", "192.168.1.2")
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 1
        assert filtered[0].ip == "192.168.1.2"

    def test_filter_by_ip_substring(self, sample_entries, filter_engine):
        """Test filtering by IP substring."""
        filter_engine.set_filter("ip", "192.168")
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 4  # All entries match

    def test_filter_by_method(self, sample_entries, filter_engine):
        """Test filtering by HTTP method."""
        filter_engine.set_filter("method", "POST")
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 1
        assert filtered[0].method == "POST"

    def test_filter_by_path(self, sample_entries, filter_engine):
        """Test filtering by path (substring match)."""
        filter_engine.set_filter("path", "/login")
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 1
        assert filtered[0].path == "/login"

    def test_filter_by_source(self, sample_entries, filter_engine):
        """Test filtering by source file."""
        filter_engine.set_filter("source", "Server1")
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 4  # All entries from Server1

    def test_combined_filters(self, sample_entries, filter_engine):
        """Test combining multiple filters (AND logic)."""
        filter_engine.set_filter("method", "GET")
        filter_engine.set_filter("status", 200)
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 1

    def test_clear_filters(self, sample_entries, filter_engine):
        """Test clearing all filters."""
        filter_engine.set_filter("status", 200)
        filter_engine.clear_filters()
        
        assert not filter_engine.is_active()
        filtered = filter_engine.apply(sample_entries)
        assert len(filtered) == len(sample_entries)

    def test_get_active_filters(self, filter_engine):
        """Test getting active filters."""
        filter_engine.set_filter("status", 401)
        filter_engine.set_filter("method", "POST")
        
        active = filter_engine.get_active_filters()
        
        assert "status" in active
        assert "method" in active
        assert active["status"] == 401
        assert active["method"] == "POST"

    def test_filter_case_insensitive_method(self, sample_entries, filter_engine):
        """Test that method filter is case insensitive."""
        filter_engine.set_filter("method", "post")  # lowercase
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 1
        assert filtered[0].method == "POST"

    def test_filter_case_insensitive_path(self, sample_entries, filter_engine):
        """Test that path filter is case insensitive."""
        filter_engine.set_filter("path", "/LOGIN")  # uppercase
        filtered = filter_engine.apply(sample_entries)
        
        assert len(filtered) == 1
        assert filtered[0].path == "/login"
