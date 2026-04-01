"""Tests for Stats Engine."""

import pytest
from core.stats import StatsEngine, TimeBucket, RateBucket
from core.models import LogEntry
from datetime import datetime


class TestStatsEngine:
    """Test suite for Stats Engine."""

    def test_empty_entries(self):
        """Test stats with no entries."""
        engine = StatsEngine()
        stats = engine.compute()
        
        assert stats.total_requests == 0
        assert stats.unique_ips == 0
        assert stats.error_rate == 0.0

    def test_basic_stats(self, sample_entries, stats_engine):
        """Test basic statistics computation."""
        stats = stats_engine.compute()
        
        assert stats.total_requests == 4
        assert stats.unique_ips == 4
        assert stats.status_2xx == 1
        assert stats.status_4xx == 2
        assert stats.status_5xx == 1

    def test_error_rate_calculation(self, sample_entries, stats_engine):
        """Test error rate calculation."""
        stats = stats_engine.compute()
        
        # 3 errors out of 4 = 75%
        assert stats.error_rate == 75.0

    def test_status_code_breakdown(self, sample_entries, stats_engine):
        """Test status code breakdown."""
        stats = stats_engine.compute()
        
        assert stats.status_2xx == 1  # 200
        assert stats.status_3xx == 0
        assert stats.status_4xx == 2  # 401, 403
        assert stats.status_5xx == 1  # 500

    def test_top_ips(self, sample_entries, stats_engine):
        """Test top IPs calculation."""
        stats = stats_engine.compute()
        
        assert len(stats.top_ips) > 0
        assert all(isinstance(ip, tuple) for ip in stats.top_ips)

    def test_top_paths(self, sample_entries, stats_engine):
        """Test top paths calculation."""
        stats = stats_engine.compute()
        
        assert len(stats.top_paths) > 0
        assert all(isinstance(path, tuple) for path in stats.top_paths)

    def test_methods_count(self, sample_entries, stats_engine):
        """Test HTTP methods count."""
        stats = stats_engine.compute()
        
        assert "GET" in stats.methods
        assert "POST" in stats.methods

    def test_hourly_traffic(self, sample_entries, stats_engine):
        """Test hourly traffic aggregation."""
        hourly = stats_engine.get_hourly_traffic()
        
        assert isinstance(hourly, list)
        if hourly:
            assert all(isinstance(bucket, TimeBucket) for bucket in hourly)
            assert all(bucket.request_count > 0 for bucket in hourly)

    def test_minutely_rates(self, sample_entries, stats_engine):
        """Test minutely rate calculation."""
        rates = stats_engine.get_minutely_rates()
        
        assert isinstance(rates, list)
        if rates:
            assert all(isinstance(bucket, RateBucket) for bucket in rates)

    def test_peak_minutes(self, sample_entries, stats_engine):
        """Test peak minutes detection."""
        peaks = stats_engine.get_peak_minutes(top_n=5)
        
        assert isinstance(peaks, list)
        assert len(peaks) <= 5

    def test_spike_detection(self, sample_entries, stats_engine):
        """Test traffic spike detection."""
        spikes = stats_engine.detect_traffic_spikes(threshold_multiplier=2.0)
        
        assert isinstance(spikes, list)

    def test_error_rate_trend(self, sample_entries, stats_engine):
        """Test error rate trend calculation."""
        trend = stats_engine.get_error_rate_trend(buckets=24)
        
        assert isinstance(trend, list)
        assert all(isinstance(rate, float) for rate in trend)

    def test_status_distribution(self, sample_entries, stats_engine):
        """Test status code distribution."""
        distribution = stats_engine.get_status_distribution()
        
        assert isinstance(distribution, dict)
        assert 200 in distribution or len(distribution) == 0

    def test_get_error_entries(self, sample_entries, stats_engine):
        """Test getting error entries."""
        errors = stats_engine.get_error_entries()
        
        assert isinstance(errors, list)
        assert all(entry.status >= 400 for entry in errors)

    def test_get_entries_by_status(self, sample_entries, stats_engine):
        """Test filtering entries by status."""
        success_entries = stats_engine.get_entries_by_status(200)
        
        assert isinstance(success_entries, list)
        assert all(entry.status == 200 for entry in success_entries)

    def test_per_source_stats(self, sample_entries, stats_engine):
        """Test per-source statistics."""
        stats = stats_engine.compute()
        
        assert "sources" in stats.source_stats or len(stats.sources) > 0
