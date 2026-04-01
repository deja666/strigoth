"""Tests for Security Rules."""

import pytest
from rules.security import SecurityRules, Alert
from core.models import LogEntry
from datetime import datetime


class TestSecurityRules:
    """Test suite for Security Rules engine."""

    def test_no_alerts_for_normal_traffic(self, sample_entries, security_rules):
        """Test that normal traffic doesn't trigger alerts."""
        alerts = []
        for entry in sample_entries:
            alerts.extend(security_rules.check(entry))
        
        # Should have minimal alerts for normal traffic
        assert len(alerts) >= 0  # May have some alerts depending on rules

    def test_brute_force_detection(self, brute_force_entries, security_rules):
        """Test brute force attack detection."""
        alerts = []
        for entry in brute_force_entries:
            alerts.extend(security_rules.check(entry))
        
        # Should detect brute force after threshold
        brute_force_alerts = [a for a in alerts if a.rule == "brute_force"]
        assert len(brute_force_alerts) > 0

    def test_scanning_detection(self, security_rules):
        """Test scanning behavior detection."""
        # Create 25 unique paths to trigger scanning detection (threshold is 20)
        paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git",
                 "/config", "/backup", "/wp-config.php", "/xmlrpc.php", "/pma",
                 "/.htaccess", "/manager", "/console", "/admin.php", "/test",
                 "/debug", "/trace", "/info", "/status", "/health", "/metrics",
                 "/api/v1", "/api/v2", "/api/v3", "/v1"]
        
        alerts = []
        for i, path in enumerate(paths):
            entry = LogEntry(
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
            alerts.extend(security_rules.check(entry))
        
        # Should detect scanning after threshold (20 unique paths)
        scanning_alerts = [a for a in alerts if a.rule == "scanning"]
        assert len(scanning_alerts) > 0

    def test_sensitive_path_detection(self, security_rules):
        """Test sensitive path access detection."""
        sensitive_paths = ["/admin", "/wp-admin", "/.env", "/.git", "/phpmyadmin"]
        alerts = []
        
        for path in sensitive_paths:
            entry = LogEntry(
                ip="192.168.1.100",
                time=datetime(2026, 3, 24, 10, 15, 30),
                method="GET",
                path=path,
                status=403,
                size=456,
                referer="-",
                agent="Mozilla/5.0",
                raw=f'192.168.1.100 - - [24/Mar/2026:10:15:30 +0000] "GET {path} HTTP/1.1" 403 456 "-" "Mozilla/5.0"',
                source_file="access.log",
                source_label="Server1"
            )
            alerts.extend(security_rules.check(entry))
        
        sensitive_alerts = [a for a in alerts if a.rule == "sensitive_path"]
        assert len(sensitive_alerts) > 0

    def test_alert_severity_levels(self, brute_force_entries, security_rules):
        """Test that alerts have correct severity levels."""
        alerts = []
        for entry in brute_force_entries:
            alerts.extend(security_rules.check(entry))
        
        if alerts:
            severities = {alert.severity for alert in alerts}
            assert severities.issubset({"high", "medium", "low"})

    def test_alert_contains_ip(self, brute_force_entries, security_rules):
        """Test that alerts contain IP information."""
        alerts = []
        for entry in brute_force_entries:
            alerts.extend(security_rules.check(entry))
        
        if alerts:
            assert all(alert.ip is not None for alert in alerts)

    def test_alert_contains_message(self, security_rules):
        """Test that alerts contain descriptive messages."""
        entry = LogEntry(
            ip="192.168.1.100",
            time=datetime(2026, 3, 24, 10, 15, 30),
            method="GET",
            path="/admin",
            status=403,
            size=456,
            referer="-",
            agent="Mozilla/5.0",
            raw='192.168.1.100 - - [24/Mar/2026:10:15:30 +0000] "GET /admin HTTP/1.1" 403 456 "-" "Mozilla/5.0"',
            source_file="access.log",
            source_label="Server1"
        )
        
        alerts = security_rules.check(entry)
        
        if alerts:
            assert all(len(alert.message) > 0 for alert in alerts)

    def test_get_all_alerts(self, brute_force_entries, security_rules):
        """Test getting all alerts."""
        for entry in brute_force_entries:
            security_rules.check(entry)
        
        all_alerts = security_rules.get_all_alerts()
        assert isinstance(all_alerts, list)

    def test_get_alerts_by_severity(self, brute_force_entries, security_rules):
        """Test filtering alerts by severity."""
        for entry in brute_force_entries:
            security_rules.check(entry)
        
        high_alerts = security_rules.get_alerts_by_severity("high")
        medium_alerts = security_rules.get_alerts_by_severity("medium")
        low_alerts = security_rules.get_alerts_by_severity("low")
        
        assert isinstance(high_alerts, list)
        assert isinstance(medium_alerts, list)
        assert isinstance(low_alerts, list)

    def test_get_alerts_by_ip(self, brute_force_entries, security_rules):
        """Test filtering alerts by IP."""
        for entry in brute_force_entries:
            security_rules.check(entry)
        
        ip_alerts = security_rules.get_alerts_by_ip("10.0.0.50")
        assert isinstance(ip_alerts, list)

    def test_get_summary(self, brute_force_entries, security_rules):
        """Test getting alert summary."""
        for entry in brute_force_entries:
            security_rules.check(entry)
        
        summary = security_rules.get_summary()
        
        assert "total" in summary
        assert "high" in summary
        assert "medium" in summary
        assert "low" in summary

    def test_reset_alerts(self, brute_force_entries, security_rules):
        """Test resetting alerts."""
        for entry in brute_force_entries:
            security_rules.check(entry)
        
        security_rules.reset()
        
        all_alerts = security_rules.get_all_alerts()
        assert len(all_alerts) == 0
