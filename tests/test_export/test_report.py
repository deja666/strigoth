"""Tests for Export functionality."""

import pytest
from pathlib import Path
from export.report import export_markdown, export_json


class TestExportMarkdown:
    """Test suite for Markdown export."""

    def test_export_markdown_creates_file(self, sample_entries, stats_engine, tmp_path):
        """Test that markdown export creates a file."""
        stats = stats_engine.compute()
        output_path = tmp_path / "test_report.md"
        
        result = export_markdown(
            stats=stats,
            filters={},
            alerts=[],
            output_path=str(output_path),
            entries=sample_entries
        )
        
        assert Path(result).exists()
        assert output_path.exists()

    def test_export_markdown_content(self, sample_entries, stats_engine, tmp_path):
        """Test markdown export content."""
        stats = stats_engine.compute()
        output_path = tmp_path / "test_report.md"
        
        export_markdown(
            stats=stats,
            filters={},
            alerts=[],
            output_path=str(output_path),
            entries=sample_entries
        )
        
        content = output_path.read_text()
        
        assert "# Log Investigation Report" in content
        assert "## Summary" in content
        assert "STATISTICS" in content or "Total" in content

    def test_export_markdown_with_alerts(self, sample_entries, stats_engine, security_rules, tmp_path):
        """Test markdown export with alerts."""
        for entry in sample_entries:
            security_rules.check(entry)
        
        stats = stats_engine.compute()
        alerts = security_rules.get_all_alerts()
        output_path = tmp_path / "test_report_alerts.md"
        
        export_markdown(
            stats=stats,
            filters={},
            alerts=alerts,
            output_path=str(output_path),
            entries=sample_entries
        )
        
        content = output_path.read_text(encoding='utf-8')
        
        assert "## Security Alerts" in content

    def test_export_markdown_with_filters(self, sample_entries, stats_engine, tmp_path):
        """Test markdown export with filters."""
        stats = stats_engine.compute()
        filters = {"status": 200, "method": "GET"}
        output_path = tmp_path / "test_report_filtered.md"
        
        export_markdown(
            stats=stats,
            filters=filters,
            alerts=[],
            output_path=str(output_path),
            entries=sample_entries
        )
        
        content = output_path.read_text()
        
        assert "## Applied Filters" in content


class TestExportJSON:
    """Test suite for JSON export."""

    def test_export_json_creates_file(self, sample_entries, stats_engine, tmp_path):
        """Test that JSON export creates a file."""
        stats = stats_engine.compute()
        output_path = tmp_path / "test_report.json"
        
        result = export_json(
            stats=stats,
            filters={},
            alerts=[],
            output_path=str(output_path),
            entries=sample_entries
        )
        
        assert Path(result).exists()
        assert output_path.exists()

    def test_export_json_valid_json(self, sample_entries, stats_engine, tmp_path):
        """Test that JSON export produces valid JSON."""
        import json
        
        stats = stats_engine.compute()
        output_path = tmp_path / "test_report.json"
        
        export_json(
            stats=stats,
            filters={},
            alerts=[],
            output_path=str(output_path),
            entries=sample_entries
        )
        
        with open(output_path, 'r') as f:
            data = json.load(f)
        
        assert "generated_at" in data
        assert "summary" in data

    def test_export_json_structure(self, sample_entries, stats_engine, tmp_path):
        """Test JSON export structure."""
        import json
        
        stats = stats_engine.compute()
        output_path = tmp_path / "test_report.json"
        
        export_json(
            stats=stats,
            filters={},
            alerts=[],
            output_path=str(output_path),
            entries=sample_entries
        )
        
        with open(output_path, 'r') as f:
            data = json.load(f)
        
        assert "version" in data
        assert "alerts_summary" in data or "alerts" in data
        assert "status_codes" in data

    def test_export_json_with_alerts(self, sample_entries, stats_engine, security_rules, tmp_path):
        """Test JSON export with alerts."""
        for entry in sample_entries:
            security_rules.check(entry)
        
        stats = stats_engine.compute()
        alerts = security_rules.get_all_alerts()
        output_path = tmp_path / "test_report_alerts.json"
        
        export_json(
            stats=stats,
            filters={},
            alerts=alerts,
            output_path=str(output_path),
            entries=sample_entries
        )
        
        import json
        with open(output_path, 'r') as f:
            data = json.load(f)
        
        assert "alerts" in data or "alerts_summary" in data
