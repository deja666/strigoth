"""Export functionality for generating investigation reports.

This module provides functions for exporting log analysis reports
in Markdown and JSON formats for documentation and integration purposes.
"""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import LogEntry
from core.stats import StatsSummary
from rules.security import Alert


def export_markdown(
    stats: StatsSummary,
    filters: Dict[str, Any],
    alerts: List[Alert],
    output_path: str,
    entries: Optional[List[LogEntry]] = None,
) -> str:
    """Generate a Markdown investigation report.
    
    Args:
        stats: Computed statistics summary
        filters: Active filters applied
        alerts: List of triggered security alerts
        output_path: Path to write the Markdown file
        entries: Optional list of log entries for appendix

    Returns:
        Path to the generated report file
    """
    lines: List[str] = []

    # Header
    lines.append("# Log Investigation Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Summary section
    lines.append("## Summary")
    lines.append("")
    stats_dict = stats.to_dict()
    for key, value in stats_dict.items():
        lines.append(f"- **{key}:** {value}")

    # Time range if available
    if stats.time_range:
        start, end = stats.time_range
        lines.append(
            f"- **Time Range:** {start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%Y-%m-%d %H:%M:%S')}"
        )
    lines.append("")

    # Top IPs
    if stats.top_ips:
        lines.append("### Top IPs by Request Count")
        lines.append("")
        lines.append("| IP | Requests |")
        lines.append("|-----|----------|")
        for ip, count in stats.top_ips[:10]:
            lines.append(f"| {ip} | {count:,} |")
        lines.append("")

    # Top Paths
    if stats.top_paths:
        lines.append("### Top Paths by Request Count")
        lines.append("")
        lines.append("| Path | Requests |")
        lines.append("|------|----------|")
        for path, count in stats.top_paths[:10]:
            lines.append(f"| {path} | {count:,} |")
        lines.append("")

    # Applied Filters
    lines.append("## Applied Filters")
    lines.append("")
    if filters:
        for key, value in filters.items():
            lines.append(f"- **{key}:** {value}")
    else:
        lines.append("*No filters applied*")
    lines.append("")

    # Security Alerts
    lines.append("## Security Alerts")
    lines.append("")

    if alerts:
        # Summary by severity
        high_count = sum(1 for a in alerts if a.severity == "high")
        medium_count = sum(1 for a in alerts if a.severity == "medium")
        low_count = sum(1 for a in alerts if a.severity == "low")

        lines.append(
            f"**Total Alerts:** {len(alerts)} (High: {high_count}, Medium: {medium_count}, Low: {low_count})"
        )
        lines.append("")

        # High severity first
        for severity in ["high", "medium", "low"]:
            severity_alerts = [a for a in alerts if a.severity == severity]
            if severity_alerts:
                lines.append(f"### {severity.upper()} Severity")
                lines.append("")
                for alert in severity_alerts[:20]:  # Limit to 20 per severity
                    lines.append(f"- ⚠️ **{alert.rule}:** {alert.message}")
                    if alert.count > 1:
                        lines.append(f"  - Count: {alert.count}")
                    if alert.first_seen and alert.last_seen:
                        lines.append(
                            f"  - First seen: {alert.first_seen.strftime('%H:%M:%S')}, Last seen: {alert.last_seen.strftime('%H:%M:%S')}"
                        )
                lines.append("")
    else:
        lines.append("*No security alerts triggered*")
        lines.append("")

    # Status Code Distribution
    lines.append("## Status Code Distribution")
    lines.append("")
    lines.append(f"- **2xx (Success):** {stats.status_2xx:,}")
    lines.append(f"- **3xx (Redirect):** {stats.status_3xx:,}")
    lines.append(f"- **4xx (Client Error):** {stats.status_4xx:,}")
    lines.append(f"- **5xx (Server Error):** {stats.status_5xx:,}")
    lines.append("")

    # HTTP Methods
    if stats.methods:
        lines.append("## HTTP Methods")
        lines.append("")
        for method, count in sorted(stats.methods.items(), key=lambda x: -x[1]):
            lines.append(f"- **{method}:** {count:,}")
        lines.append("")

    # Appendix - Recent Entries
    if entries:
        lines.append("## Appendix: Recent Log Entries")
        lines.append("")
        lines.append("```")
        # Show last 50 entries
        for entry in entries[-50:]:
            time_str = entry.time.strftime("%H:%M:%S")
            lines.append(f"{time_str} {entry.ip:15} {entry.method:6} {entry.path:30} {entry.status}")
        lines.append("```")
        lines.append("")

    # Write to file
    content = "\n".join(lines)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as f:
        f.write(content)

    return str(output)


def export_json(
    stats: StatsSummary,
    filters: Dict[str, Any],
    alerts: List[Alert],
    output_path: str,
    entries: Optional[List[LogEntry]] = None,
) -> str:
    """Generate a JSON investigation report.
    
    Args:
        stats: Computed statistics summary
        filters: Active filters applied
        alerts: List of triggered security alerts
        output_path: Path to write the JSON file
        entries: Optional list of log entries for recent entries

    Returns:
        Path to the generated report file
    """
    import json

    # Convert alerts to serializable format
    alerts_data: List[Dict[str, Any]] = []
    for alert in alerts:
        alerts_data.append(
            {
                "rule": alert.rule,
                "severity": alert.severity,
                "message": alert.message,
                "ip": alert.ip,
                "path": alert.path,
                "count": alert.count,
                "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
                "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
            }
        )

    # Build report
    report: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "version": "v0.10",
        "summary": stats.to_dict(),
        "filters": filters,
        "alerts": alerts_data,
        "alerts_summary": {
            "total": len(alerts),
            "high": sum(1 for a in alerts if a.severity == "high"),
            "medium": sum(1 for a in alerts if a.severity == "medium"),
            "low": sum(1 for a in alerts if a.severity == "low"),
        },
        "status_codes": {
            "2xx": stats.status_2xx,
            "3xx": stats.status_3xx,
            "4xx": stats.status_4xx,
            "5xx": stats.status_5xx,
        },
        "methods": stats.methods,
        "top_ips": [
            {"ip": ip, "count": count} for ip, count in stats.top_ips
        ],
        "top_paths": [
            {"path": path, "count": count} for path, count in stats.top_paths
        ],
    }

    # Add time range
    if stats.time_range:
        start, end = stats.time_range
        report["time_range"] = {
            "start": start.isoformat(),
            "end": end.isoformat(),
        }

    # Add recent entries if provided
    if entries:
        recent_entries = []
        for entry in entries[-20:]:  # Last 20 entries
            recent_entries.append({
                "time": entry.time.isoformat(),
                "ip": entry.ip,
                "method": entry.method,
                "path": entry.path,
                "status": entry.status,
                "size": entry.size,
            })
        report["recent_entries"] = recent_entries

    # Write to file
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return str(output)
