#!/usr/bin/env python3
"""Test script for Strigoth Log Investigator components."""

def test_parser():
    """Test nginx parser."""
    from parser.nginx import parse_line
    
    line = '192.168.1.1 - - [24/Mar/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0"'
    result = parse_line(line)
    
    assert result is not None, "Parser failed"
    assert result.ip == "192.168.1.1"
    assert result.method == "GET"
    assert result.path == "/"
    assert result.status == 200
    print("✓ Parser test passed")


def test_loader():
    """Test log loader."""
    from core.loader import LogLoader
    
    loader = LogLoader("sample_logs/access.log")
    entries = loader.load()
    
    assert len(entries) > 0, "No entries loaded"
    print(f"✓ Loader test passed ({len(entries)} entries)")
    return entries


def test_stats(entries):
    """Test statistics engine."""
    from core.stats import StatsEngine
    
    stats_engine = StatsEngine()
    stats_engine.load(entries)
    stats = stats_engine.compute()
    
    assert stats.total_requests > 0
    assert stats.unique_ips > 0
    print(f"✓ Stats test passed (Unique IPs: {stats.unique_ips}, Error rate: {stats.error_rate:.1f}%)")


def test_filters(entries):
    """Test filter engine."""
    from core.filter_engine import FilterEngine
    
    filter_engine = FilterEngine()
    
    # Test status filter
    filter_engine.set_filter("status", 401)
    filtered = filter_engine.apply(entries)
    assert len(filtered) > 0, "Status filter failed"
    print(f"✓ Filter test passed ({len(filtered)} entries with status 401)")
    
    # Test clear
    filter_engine.clear_filters()
    assert not filter_engine.is_active()
    print("✓ Clear filters test passed")


def test_security_rules(entries):
    """Test security rules engine."""
    from rules.security import SecurityRules
    
    rules = SecurityRules()
    alerts = []
    
    for entry in entries:
        alerts.extend(rules.check(entry))
    
    assert len(alerts) > 0, "No alerts triggered"
    print(f"✓ Security rules test passed ({len(alerts)} alerts)")
    
    # Check for brute force detection
    brute_force_alerts = [a for a in alerts if a.rule == "brute_force"]
    if brute_force_alerts:
        print(f"  - Brute force alerts: {len(brute_force_alerts)}")
    
    # Check for sensitive path alerts
    sensitive_alerts = [a for a in alerts if a.rule == "sensitive_path"]
    if sensitive_alerts:
        print(f"  - Sensitive path alerts: {len(sensitive_alerts)}")


def test_export(entries):
    """Test export functionality."""
    from core.stats import StatsEngine
    from rules.security import SecurityRules
    from export.report import export_markdown
    from pathlib import Path
    
    # Setup
    stats_engine = StatsEngine()
    stats_engine.load(entries)
    stats = stats_engine.compute()
    
    rules = SecurityRules()
    for entry in entries:
        rules.check(entry)
    
    # Export
    output_path = "reports/test_report.md"
    result = export_markdown(
        stats=stats,
        filters={"status": 401},
        alerts=rules.get_all_alerts(),
        output_path=output_path,
        entries=entries,
    )
    
    # Verify file exists
    assert Path(result).exists(), f"Report file not created: {result}"
    print(f"✓ Export test passed (Report: {result})")


def main():
    """Run all tests."""
    print("=" * 50)
    print("Strigoth Log Investigator - Component Tests")
    print("=" * 50)
    
    try:
        test_parser()
        entries = test_loader()
        test_stats(entries)
        test_filters(entries)
        test_security_rules(entries)
        test_export(entries)
        
        print("=" * 50)
        print("✅ All tests passed!")
        print("=" * 50)
        
    except AssertionError as e:
        print(f"❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
