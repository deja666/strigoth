"""Strigoth Log Investigator TUI - Main Application.

A modern terminal user interface for investigating web server logs with
focus on security analysis, anomaly detection, and fast filtering.

Features:
- Interactive DataTable viewer with sorting
- Multi-criteria filtering (status, IP, method, path, source, search)
- Rule-based anomaly detection (brute force, scanning, high rate)
- Real-time statistics dashboard
- Security alerts panel
- Live log mode (tail -f style)
- Time-based charts with sparklines
- Request rate visualization
- Markdown & JSON export
- Custom YAML configuration
- Multi-log file support
- Auto-detect log format (Nginx/Apache)
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from core.config import reload_config
from core.filter_engine import FilterEngine, FilterState
from core.loader import LogLoader, MultiLogLoader
from core.models import LogEntry
from core.stats import StatsEngine
from export.report import export_json, export_markdown
from rules.security import SecurityRules
from tui.charts import render_charts_dashboard, render_rate_dashboard
from tui.modals import ExportModal, FilterModal, HelpModal, LogDetailModal, PresetModal


class LogInvestigatorApp(App):
    """
    Strigoth Log Investigator - Clean Professional TUI
    """

    CSS_PATH = "app.tcss"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("f", "open_filter", "Filter"),
        ("c", "clear_filters", "Clear"),
        ("s", "toggle_info", "Info"),
        ("a", "show_alerts", "Alerts"),
        ("t", "show_charts", "Charts"),
        ("r", "reload", "Reload"),
        ("e", "export_report", "Export"),
        ("o", "open_config", "Config"),
        ("?", "show_help", "Help"),
        ("j", "scroll_down", "Down"),
        ("k", "scroll_up", "Up"),
        ("l", "toggle_live", "Live"),
        ("P", "manage_presets", "Presets"),
        ("g", "go_top", "Top"),
        ("G", "go_bottom", "Bottom"),
    ]

    TITLE = "STRIGOTH"
    SUB_TITLE = "v1.3.0"

    # Reactive state
    show_stats = reactive(True)
    current_view = reactive("stats")  # "stats", "alerts", or "charts"
    live_mode = reactive(False)
    auto_scroll = reactive(True)

    def __init__(self, log_paths: Optional[List[str]] = None) -> None:
        """Initialize the application.

        Args:
            log_paths: List of log file paths (supports multiple files)
        """
        super().__init__()
        self.log_paths = log_paths or []
        self.multi_loader = MultiLogLoader()
        self.loader: Optional[LogLoader] = None
        self.entries: List[LogEntry] = []
        self.filtered_entries: List[LogEntry] = []
        self.filter_engine = FilterEngine()
        self.stats_engine = StatsEngine()
        self.security_rules = SecurityRules()
        self.stats: Optional[StatsSummary] = None
        self.file_position = 0  # For live mode tracking
        self._live_timer: Any = None  # For periodic file checking
        self.show_source_column = False  # Show source column when multiple files
        self._filter_cache: Optional[List[LogEntry]] = (
            None  # Filter cache for performance
        )

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("No filters active", id="filter-display")

        with Horizontal(id="main-container"):
            with Vertical(id="log-panel"):
                yield DataTable(id="log-table")
            with Vertical(id="info-panel"):
                with TabbedContent(initial="stats"):
                    with TabPane("📊 Stats", id="stats"):
                        yield RichLog(id="stats-content", highlight=True, markup=True)
                    with TabPane("🚨 Alerts", id="alerts"):
                        yield RichLog(id="alerts-content", highlight=True, markup=True)
                    with TabPane("📈 Charts", id="charts"):
                        yield RichLog(id="charts-content", highlight=True, markup=True)

        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        """Initialize."""
        # Setup DataTable - columns will be added in _load_log_files
        table = self.query_one("#log-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True

        # Load data
        if self.log_paths:
            self._load_log_files()
        else:
            self.notify(
                "Usage: python -m tui.app <logfile1> [logfile2] ...", severity="warning"
            )

    def _load_log_files(self) -> None:
        """Load log files (supports multiple files)."""
        try:
            table = self.query_one("#log-table", DataTable)
            table.loading = True

            # Load all files
            self.entries = self.multi_loader.load_files(self.log_paths)

            # Determine if we need source column
            self.show_source_column = len(self.log_paths) > 1

            # Clear and setup columns
            table.clear(columns=True)  # Clear columns too
            if self.show_source_column:
                table.add_columns(
                    "Time",
                    "Source",
                    "IP Address",
                    "Method",
                    "Path",
                    "Status",
                    "Size",
                )
            else:
                table.add_columns(
                    "Time",
                    "IP Address",
                    "Method",
                    "Path",
                    "Status",
                    "Size",
                )

            # Process security rules
            self.security_rules.reset()
            for entry in self.entries:
                self.security_rules.check(entry)

            # Stats
            self.stats_engine.load(self.entries)
            self.stats = self.stats_engine.compute()

            # Invalidate cache and apply filters
            self._invalidate_filter_cache()
            self._apply_filters()

            table.loading = False

            # Focus the table so Enter key works immediately
            table.focus()

            file_count = self.multi_loader.get_file_count()
            total_entries = self.multi_loader.get_total_count()
            self.notify(f"Loaded {total_entries:,} entries from {file_count} file(s)")

        except FileNotFoundError as e:
            self.notify(f"File not found: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def _show_detail_modal(self, entry_index: int) -> None:
        """Show detail modal for entry at given index.

        Args:
            entry_index: Index in filtered_entries list
        """
        if 0 <= entry_index < len(self.filtered_entries):
            log_entry = self.filtered_entries[entry_index]

            def handle_navigation(result: Any) -> None:
                """Handle modal dismissal and navigation."""
                if result and isinstance(result, dict):
                    action = result.get("action")

                    if action == "navigate":
                        # User pressed n or p, open new modal
                        self._show_detail_modal(result["index"])
                    elif action == "filter_ip":
                        # User pressed f, apply filter
                        ip = result.get("ip")
                        if ip:
                            # Replace current filters with IP filter
                            self.filter_engine.filters = FilterState(ip=ip)

                            # Invalidate cache and apply filters
                            self._invalidate_filter_cache()
                            self._apply_filters()

                            self.notify(f"Filtered by IP: {ip}")

            self.push_screen(
                LogDetailModal(log_entry, entry_index, self.filtered_entries),
                handle_navigation,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle DataTable row selection (Enter key press).

        Args:
            event: RowSelected event from DataTable
        """
        # Get the row key from the event
        row_key = event.row_key

        # Convert to string and extract index
        row_key_str = str(row_key.value)
        if row_key_str.startswith("row_"):
            idx = int(row_key_str.split("_")[1])

            # Check bounds and show modal
            if 0 <= idx < len(self.filtered_entries):
                self._show_detail_modal(idx)

    def watch_live_mode(self, live: bool) -> None:
        """Handle live mode state changes."""
        if live:
            self.notify("🔴 LIVE MODE ON - Press L to toggle off", timeout=3)
            self._start_live_monitoring()
        else:
            self.notify("⚪ LIVE MODE OFF", timeout=2)
            self._stop_live_monitoring()

    def _start_live_monitoring(self) -> None:
        """Start periodic file monitoring."""
        if self._live_timer:
            return

        # Check every 1 second
        self._live_timer = self.set_interval(1.0, self._check_for_new_logs)

    def _stop_live_monitoring(self) -> None:
        """Stop periodic file monitoring."""
        if self._live_timer:
            self._live_timer.stop()
            self._live_timer = None

    def _check_for_new_logs(self) -> None:
        """Check for new log entries (called periodically)."""
        if not self.live_mode or not self.loader:
            return

        try:
            new_entries, new_position = self.loader.read_new_lines(self.file_position)

            if new_entries:
                # Add new entries
                self.entries.extend(new_entries)
                self.file_position = new_position

                # Re-apply filters
                self._apply_filters()

                # Auto-scroll to bottom
                if self.auto_scroll:
                    table = self.query_one("#log-table", DataTable)
                    self.call_later(lambda: table.scroll_to(y=table.max_scroll_y))

                # Show notification for new entries (throttled)
                if len(new_entries) <= 5:
                    self.notify(f"+{len(new_entries)} new entries", timeout=1)

        except Exception:
            # Silently ignore errors in live mode
            pass

    def _invalidate_filter_cache(self) -> None:
        """Invalidate filter cache when filters change."""
        self._filter_cache = None
        self.filter_cache_valid = False

    def _apply_filters(self) -> None:
        """Apply filters with caching for performance."""
        # Check if cache is valid
        if self._filter_cache is not None and self.filter_cache_valid:
            self.filtered_entries = self._filter_cache
        else:
            # Re-compute filtered entries
            self.filtered_entries = self.filter_engine.apply(self.entries)
            self._filter_cache = self.filtered_entries
            self.filter_cache_valid = True

        self._update_table()
        self._update_filter_display()
        self._update_info()
        self._update_status()

    def _update_table(self) -> None:
        """Update DataTable with color-coded status (optimized for large datasets)."""
        table = self.query_one("#log-table", DataTable)
        table.clear()

        # Optimize for large datasets - only render first 1000 rows
        max_rows = 1000
        entries_to_show = self.filtered_entries[:max_rows]

        # Add rows with keys for later retrieval
        for idx, entry in enumerate(entries_to_show):
            time_str = entry.time.strftime("%H:%M:%S")
            status_code = entry.status

            if 200 <= status_code < 300:
                status_style = "green"
            elif 300 <= status_code < 400:
                status_style = "red"
            elif 400 <= status_code < 500:
                status_style = "yellow"
            else:
                status_style = "purple"

            status_text = Text(str(status_code), style=f"bold {status_style}")
            row_key = f"row_{idx}"

            if self.show_source_column:
                table.add_row(
                    time_str,
                    entry.source_label,
                    entry.ip,
                    entry.method,
                    entry.path,
                    status_text,
                    f"{entry.size:,}",
                    key=row_key,
                )
            else:
                table.add_row(
                    time_str,
                    entry.ip,
                    entry.method,
                    entry.path,
                    status_text,
                    f"{entry.size:,}",
                    key=row_key,
                )

        # Show warning if dataset is truncated
        if len(self.filtered_entries) > max_rows:
            self.notify(
                f"Displaying first {max_rows} of {len(self.filtered_entries):,} entries",
                timeout=3,
            )

    def _update_filter_display(self) -> None:
        """Update filter bar."""
        display = self.query_one("#filter-display", Static)
        active = self.filter_engine.get_active_filters()

        if not active:
            display.update("No filters active")
        else:
            parts = [f"{k}: {v}" for k, v in active.items()]
            display.update(" | ".join(parts))

    def _update_info(self) -> None:
        """Update info panel based on active tab."""
        # Update all tabs
        self._update_stats(self.query_one("#stats-content", RichLog))
        self._update_alerts(self.query_one("#alerts-content", RichLog))
        self._update_charts(self.query_one("#charts-content", RichLog))

    def _update_stats(self, content: RichLog) -> None:
        """Update stats view."""
        content.clear()
        if not self.stats:
            content.write("No data available")
            return

        content.write("[bold]STATISTICS[/]")
        content.write("")
        content.write(f"Total: {self.stats.total_requests:,}")
        content.write(f"Unique IPs: {self.stats.unique_ips:,}")
        content.write(f"Error Rate: {self.stats.error_rate:.1f}%")
        content.write("")
        content.write(f"[green]2xx: {self.stats.status_2xx:,}[/green]")
        content.write(f"[red]3xx: {self.stats.status_3xx:,}[/red]")
        content.write(f"[yellow]4xx: {self.stats.status_4xx:,}[/yellow]")
        content.write(f"[purple]5xx: {self.stats.status_5xx:,}[/purple]")

        if self.stats.time_range:
            start, end = self.stats.time_range
            content.write("")
            content.write("[bold]Time Range:[/]")
            content.write(
                f"  {start.strftime('%H:%M:%S')} - {end.strftime('%H:%M:%S')}"
            )

        # Add Top IPs (Top 5)
        if self.stats.top_ips:
            content.write("")
            content.write("[bold]Top IPs:[/]")
            for ip, count in self.stats.top_ips[:5]:  # Show top 5 only
                content.write(f"  {ip}: {count:,} requests")

        # Add HTTP Methods breakdown
        if self.stats.methods:
            content.write("")
            content.write("[bold]HTTP Methods:[/]")
            for method, count in sorted(self.stats.methods.items()):
                content.write(f"  {method}: {count:,}")

    def _update_alerts(self, content: RichLog) -> None:
        """Update alerts view - show ALL alerts without paging."""
        content.clear()
        alerts = self.security_rules.get_all_alerts()

        if not alerts:
            content.write("[green]No security alerts detected[/green]")
            return

        # Get summary
        high_count = len([a for a in alerts if a.severity == "high"])
        medium_count = len([a for a in alerts if a.severity == "medium"])
        low_count = len([a for a in alerts if a.severity == "low"])

        total_alerts = len(alerts)

        content.write("[bold]SECURITY ALERTS[/]")
        content.write(
            f"Total: {total_alerts} | [red]High: {high_count}[/red] | [yellow]Medium: {medium_count}[/yellow] | Low: {low_count}"
        )
        content.write("")
        content.write("[dim]Use J/K to scroll[/]")
        content.write("")

        # Display ALL alerts with word wrapping
        for i, alert in enumerate(alerts, 1):
            color = (
                "red"
                if alert.severity == "high"
                else "yellow"
                if alert.severity == "medium"
                else "green"
            )

            # Format alert with wrapping
            content.write(f"[bold]{i}. [{color}]{alert.severity.upper()}[/]")

            # Wrap message text
            message = alert.message
            if len(message) > 50:
                # Split long messages
                words = message.split()
                line = ""
                for word in words:
                    if len(line) + len(word) > 48:
                        content.write(f"   {line}")
                        line = word + " "
                    else:
                        line += word + " "
                if line:
                    content.write(f"   {line}")
            else:
                content.write(f"   {message}")

            if alert.count > 1:
                content.write(f"   [dim]Count: {alert.count}[/]")
            if alert.ip:
                content.write(f"   [dim]IP: {alert.ip}[/]")
            content.write("")

    def _update_charts(self, content: RichLog) -> None:
        """Update charts view."""
        content.clear()
        if not self.stats:
            content.write("No data available for charts")
            return

        # Get hourly traffic
        hourly = self.stats_engine.get_hourly_traffic()
        hourly_data = [(b.timestamp.strftime("%H:00"), b.request_count) for b in hourly]

        # Get error rate trend
        error_rates = self.stats_engine.get_error_rate_trend()

        # Render original charts
        chart_text = render_charts_dashboard(
            hourly_traffic=hourly_data,
            error_rates=error_rates,
            status_2xx=self.stats.status_2xx,
            status_3xx=self.stats.status_3xx,
            status_4xx=self.stats.status_4xx,
            status_5xx=self.stats.status_5xx,
        )

        # Write original charts
        content.write("")
        for line in chart_text.split("\n"):
            content.write(line)

        # Get request rate data
        minutely_rates = self.stats_engine.get_minutely_rates(limit=60)
        peak_minutes = self.stats_engine.get_peak_minutes(top_n=5)
        spikes = self.stats_engine.detect_traffic_spikes(threshold_multiplier=2.0)

        # Render rate dashboard
        content.write("")
        content.write("─" * 50)
        content.write("")
        rate_text = render_rate_dashboard(
            minutely_rates=minutely_rates,
            peak_minutes=peak_minutes,
            spikes=spikes,
        )

        # Write rate dashboard
        for line in rate_text.split("\n"):
            content.write(line)

    def _update_status(self) -> None:
        """Update status bar."""
        status_bar = self.query_one("#status-bar", Static)
        total = len(self.entries)
        filtered = len(self.filtered_entries)
        alerts_count = len(self.security_rules.get_all_alerts())

        if total == 0:
            status_bar.update("")
            return

        error_count = sum(1 for e in self.filtered_entries if e.status >= 400)
        error_rate = (error_count / filtered * 100) if filtered > 0 else 0

        # Add LIVE indicator
        live_indicator = "[bold red]🔴 LIVE[/] | " if self.live_mode else ""

        status_bar.update(
            f"{live_indicator}Showing {filtered:,} of {total:,} | "
            f"Errors: {error_count} ({error_rate:.1f}%) | "
            f"Alerts: {alerts_count}"
        )

    def on_tab_changed(self, event: TabbedContent.TabActivated) -> None:
        """Handle tab change event."""
        # Optionally update content when tab changes
        pass

    def action_open_filter(self) -> None:
        """Open filter modal."""

        def handle_filters(filters: Optional[FilterState]) -> None:
            if filters is not None:
                self.filter_engine.filters = filters
                self._invalidate_filter_cache()
                self._apply_filters()

        self.push_screen(FilterModal(self.filter_engine.filters), handle_filters)

    def action_manage_presets(self) -> None:
        """Open preset manager modal."""

        def handle_preset_result(result: Optional[Dict[str, Any]]) -> None:
            if result and result.get("action") == "load":
                filter_state = result.get("filter")
                if filter_state:
                    self.filter_engine.filters = filter_state
                    self._invalidate_filter_cache()
                    self._apply_filters()
                    self.notify("Preset loaded successfully.")

        self.push_screen(PresetModal(self.filter_engine.filters), handle_preset_result)

    def action_clear_filters(self) -> None:
        """Clear filters."""
        self.filter_engine.clear_filters()
        self._invalidate_filter_cache()
        self._apply_filters()
        self.notify("Filters cleared")

    def action_toggle_info(self) -> None:
        """Toggle info panel visibility."""
        self.show_stats = not self.show_stats
        info_panel = self.query_one("#info-panel")
        info_panel.set_class(not self.show_stats, "hidden")

    def action_toggle_live(self) -> None:
        """Toggle live mode on/off."""
        if not self.log_paths:
            self.notify("No log file loaded", severity="warning")
            return
        self.live_mode = not self.live_mode

    def action_show_alerts(self) -> None:
        """Switch to alerts tab."""
        self.query_one(TabbedContent).active = "alerts"
        self.notify("Alerts view - press j/k to scroll")

    def action_show_charts(self) -> None:
        """Switch to charts tab."""
        self.query_one(TabbedContent).active = "charts"
        self.notify("Charts view - traffic visualization")

    def action_reload(self) -> None:
        """Reload log files."""
        if self.log_paths:
            self._load_log_files()

    def action_open_config(self) -> None:
        """Open config file info."""
        config_path = Path("config.yaml").absolute()

        # Reload config
        try:
            reload_config()
            self.notify(f"Config reloaded from: {config_path}")
        except Exception as e:
            self.notify(f"Config reload failed: {e}", severity="error")

        # Show config path
        self.notify(f"Config file: {config_path}", timeout=5)

    def action_export_report(self) -> None:
        """Export report with format selection."""
        if not self.stats:
            self.notify("No data to export", severity="warning")
            return

        def handle_export(format_choice: Optional[str]) -> None:
            if not format_choice:
                return

            # Generate file paths
            if self.log_paths:
                base_name = Path(self.log_paths[0]).stem
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                md_path = f"reports/{base_name}_report_{timestamp}.md"
                json_path = f"reports/{base_name}_report_{timestamp}.json"
            else:
                md_path = "reports/log_report.md"
                json_path = "reports/log_report.json"

            stats = self.stats
            filters = self.filter_engine.get_active_filters()
            alerts = self.security_rules.get_all_alerts()
            entries = self.filtered_entries

            try:
                if format_choice == "export-md":
                    # Markdown only
                    export_markdown(
                        stats=stats,
                        filters=filters,
                        alerts=alerts,
                        output_path=md_path,
                        entries=entries,
                    )
                    self.notify(f"📄 Markdown exported: {md_path}")

                elif format_choice == "export-json":
                    # JSON only
                    export_json(
                        stats=stats,
                        filters=filters,
                        alerts=alerts,
                        output_path=json_path,
                        entries=entries,
                    )
                    self.notify(f"📋 JSON exported: {json_path}")

                elif format_choice == "export-both":
                    # Both formats
                    export_markdown(
                        stats=stats,
                        filters=filters,
                        alerts=alerts,
                        output_path=md_path,
                        entries=entries,
                    )
                    export_json(
                        stats=stats,
                        filters=filters,
                        alerts=alerts,
                        output_path=json_path,
                        entries=entries,
                    )
                    self.notify("✅ Both formats exported!")

            except Exception as e:
                self.notify(f"Export failed: {e}", severity="error")

        # Show export modal
        self.push_screen(ExportModal(), handle_export)

    def action_show_help(self) -> None:
        """Show help."""
        self.push_screen(HelpModal())

    def action_scroll_down(self) -> None:
        """Scroll down based on current view."""
        if self.current_view == "alerts":
            # Scroll alerts content (RichLog has built-in scroll)
            content = self.query_one("#info-content", RichLog)
            content.scroll_relative(y=3)
        else:
            # Default: scroll log table
            table = self.query_one("#log-table", DataTable)
            table.scroll_relative(y=5)

    def action_scroll_up(self) -> None:
        """Scroll up based on current view."""
        if self.current_view == "alerts":
            # Scroll alerts content (RichLog has built-in scroll)
            content = self.query_one("#info-content", RichLog)
            content.scroll_relative(y=-3)
        else:
            # Default: scroll log table
            table = self.query_one("#log-table", DataTable)
            table.scroll_relative(y=-5)

    def action_go_top(self) -> None:
        """Go to top."""
        table = self.query_one("#log-table", DataTable)
        table.scroll_to(y=0)

    def action_go_bottom(self) -> None:
        """Go to bottom of log table."""
        table = self.query_one("#log-table", DataTable)
        table.scroll_to(y=table.max_scroll_y)


def main() -> None:
    """Entry point for the application."""
    log_paths = sys.argv[1:] if len(sys.argv) > 1 else []
    app = LogInvestigatorApp(log_paths)
    app.run()


def make_app() -> LogInvestigatorApp:
    """Create app instance for textual run (development)."""
    return LogInvestigatorApp("sample_logs/access.log")


if __name__ == "__main__":
    main()
