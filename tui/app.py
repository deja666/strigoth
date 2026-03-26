"""
Strigoth Log Investigator TUI - Clean Professional Design
No emojis, no scrollbars issues, working colors.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from rich.text import Text
from textual.app import App, ComposeResult
from textual.color import Color
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Placeholder,
    RichLog,
    Static,
)

from core.filter_engine import FilterEngine, FilterState
from core.loader import LogLoader, MultiLogLoader
from core.models import LogEntry
from core.stats import StatsEngine
from core.config import get_config, reload_config
from export.report import export_markdown, export_json
from rules.security import Alert, SecurityRules
from tui.charts import render_charts_dashboard


class FilterModal(ModalScreen):
    """Filter modal - clean design."""

    BINDINGS = [
        ("escape", "close", "Close"),
        ("enter", "apply", "Apply"),
    ]

    def __init__(self, current_filters: FilterState) -> None:
        super().__init__()
        self.current_filters = current_filters

    def compose(self) -> ComposeResult:
        with Container(id="filter-modal"):
            yield Static("FILTER OPTIONS", id="filter-modal-title")
            yield Label("Status Code:")
            yield Input(
                value=str(self.current_filters.status)
                if self.current_filters.status
                else "",
                id="filter-status",
                type="integer",
            )
            yield Label("IP Address:")
            yield Input(
                value=self.current_filters.ip or "",
                id="filter-ip",
            )
            yield Label("HTTP Method:")
            yield Input(
                value=self.current_filters.method or "",
                id="filter-method",
            )
            yield Label("Path:")
            yield Input(
                value=self.current_filters.path or "",
                id="filter-path",
            )
            yield Label("Source:")
            yield Input(
                value=self.current_filters.source or "",
                id="filter-source",
                placeholder="e.g., access, server2",
            )
            with Horizontal(id="filter-modal-buttons"):
                yield Button("APPLY", id="apply", variant="primary")
                yield Button("CLEAR", id="clear", variant="warning")
                yield Button("CANCEL", id="cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            self._apply_filters()
        elif event.button.id == "clear":
            self._clear_filters()
        elif event.button.id == "cancel":
            self.dismiss(None)

    def _apply_filters(self) -> None:
        """Apply filters from modal."""
        status_input = self.query_one("#filter-status", Input).value
        method = self.query_one("#filter-method", Input).value
        ip = self.query_one("#filter-ip", Input).value
        path = self.query_one("#filter-path", Input).value
        source = self.query_one("#filter-source", Input).value

        filters = FilterState(
            status=int(status_input) if status_input else None,
            method=method.upper() if method else None,
            ip=ip if ip else None,
            path=path if path else None,
            source=source if source else None,
        )
        self.dismiss(filters)

    def _clear_filters(self) -> None:
        for widget_id in ["filter-status", "filter-method", "filter-ip", "filter-path", "filter-source"]:
            self.query_one(f"#{widget_id}", Input).value = ""

    def action_close(self) -> None:
        self.dismiss(None)

    def action_apply(self) -> None:
        self._apply_filters()


class ExportModal(ModalScreen):
    """Export format selection modal."""

    BINDINGS = [
        ("escape", "close", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="export-modal"):
            yield Static("EXPORT REPORT", id="export-modal-title")
            yield Static("Select export format:", id="export-modal-label")
            with Horizontal(id="export-modal-buttons"):
                yield Button("📄 Markdown", id="export-md", variant="primary")
                yield Button("📋 JSON", id="export-json", variant="default")
                yield Button("Both", id="export-both", variant="default")
                yield Button("Cancel", id="export-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id in ["export-md", "export-json", "export-both"]:
            self.dismiss(event.button.id)
        elif event.button.id == "export-cancel":
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class HelpModal(ModalScreen):
    """Help modal - clean design."""

    BINDINGS = [
        ("escape", "close", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="help-modal"):
            yield Static("KEYBOARD SHORTCUTS", id="help-modal-title")
            yield Static(
                "NAVIGATION:\n"
                "  f - Open filters\n"
                "  c - Clear filters\n"
                "  j/k - Scroll (focused panel)\n"
                "  g/G - Top/Bottom of log\n"
                "\n"
                "VIEW SWITCHING:\n"
                "  s - Toggle info panel\n"
                "  a - Show alerts (auto-scroll)\n"
                "  t - Show charts\n"
                "  TAB - Switch between panels\n"
                "\n"
                "LIVE MODE:\n"
                "  l - Toggle live mode (tail -f style)\n"
                "\n"
                "CONFIG & EXPORT:\n"
                "  o - Open/reload config (YAML)\n"
                "  e - Export report (MD/JSON)\n"
                "  r - Reload log file\n"
                "\n"
                "OTHER:\n"
                "  ? - Show this help\n"
                "  q - Quit\n"
                "\n"
                "[dim]Tip: Press TAB to focus on different panels,[/]\n"
                "[dim]then use j/k to scroll[/]",
                id="help-content",
            )
            yield Button("CLOSE", id="close", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


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
        ("g", "go_top", "Top"),
        ("G", "go_bottom", "Bottom"),
        ("l", "toggle_live", "Live"),
    ]

    TITLE = "STRIGOTH LOG INVESTIGATOR"
    SUB_TITLE = "v1.0"

    # State
    show_stats = reactive(True)
    current_view = reactive("stats")  # "stats", "alerts", or "charts"
    live_mode = reactive(False)
    auto_scroll = reactive(True)

    def __init__(self, log_paths: Optional[List[str]] = None) -> None:
        """
        Initialize the application.

        Args:
            log_paths: List of log file paths (supports multiple files)
        """
        super().__init__()
        self.log_paths = log_paths or []
        self.multi_loader = MultiLogLoader()
        self.loader = None  # Legacy single-file loader
        self.entries: list[LogEntry] = []
        self.filtered_entries: list[LogEntry] = []
        self.filter_engine = FilterEngine()
        self.stats_engine = StatsEngine()
        self.security_rules = SecurityRules()
        self.stats = None
        self.file_position = 0  # For live mode tracking
        self._live_timer = None  # For periodic file checking
        self.show_source_column = False  # Show source column when multiple files

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("No filters active", id="filter-display")

        with Horizontal(id="main-container"):
            with Vertical(id="log-panel"):
                yield DataTable(id="log-table")
            with Vertical(id="info-panel"):
                with Horizontal(id="info-tabs"):
                    yield Button("Stats", id="btn-stats", variant="primary")
                    yield Button("Alerts", id="btn-alerts", variant="default")
                    yield Button("Charts", id="btn-charts", variant="default")
                yield RichLog(id="info-content", highlight=True, markup=True)

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
            self.notify("Usage: python -m tui.app <logfile1> [logfile2] ...", severity="warning")

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

            # Apply filters
            self._apply_filters()

            table.loading = False

            file_count = self.multi_loader.get_file_count()
            total_entries = self.multi_loader.get_total_count()
            self.notify(f"Loaded {total_entries:,} entries from {file_count} file(s)")

        except FileNotFoundError as e:
            self.notify(f"File not found: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

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

        except Exception as e:
            # Silently ignore errors in live mode
            pass

    def _apply_filters(self) -> None:
        """Apply filters."""
        self.filtered_entries = self.filter_engine.apply(self.entries)
        self._update_table()
        self._update_filter_display()
        self._update_info()
        self._update_status()

    def _update_table(self) -> None:
        """Update DataTable with color-coded status."""
        table = self.query_one("#log-table", DataTable)
        table.clear()

        for entry in self.filtered_entries:
            time_str = entry.time.strftime("%H:%M:%S")

            # Determine color based on status code
            status_code = entry.status
            if 200 <= status_code < 300:
                # 2xx - Success (Green)
                status_style = "#00ff00"
            elif 300 <= status_code < 400:
                # 3xx - Redirect (Cyan)
                status_style = "#00ffff"
            elif 400 <= status_code < 500:
                # 4xx - Client Error (Yellow)
                status_style = "#ffff00"
            else:
                # 5xx - Server Error (Red)
                status_style = "#ff0000"

            # Create styled text for status column
            status_text = Text(str(status_code), style=f"bold {status_style}")

            # Add source column if multiple files
            if self.show_source_column:
                table.add_row(
                    time_str,
                    entry.source_label,
                    entry.ip,
                    entry.method,
                    entry.path,
                    status_text,
                    f"{entry.size:,}",
                )
            else:
                table.add_row(
                    time_str,
                    entry.ip,
                    entry.method,
                    entry.path,
                    status_text,
                    f"{entry.size:,}",
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
        """Update info panel based on current view."""
        content = self.query_one("#info-content", RichLog)

        if self.current_view == "stats":
            self._update_stats(content)
        elif self.current_view == "alerts":
            self._update_alerts(content)
        elif self.current_view == "charts":
            self._update_charts(content)

    def _update_stats(self, content: RichLog) -> None:
        """Update stats view."""
        content.clear()
        if not self.stats:
            content.write("No data available")
            return

        content.write("[bold green]STATISTICS[/]")
        content.write("")
        content.write(f"Total: {self.stats.total_requests:,}")
        content.write(f"Unique IPs: {self.stats.unique_ips:,}")
        content.write(f"Error Rate: {self.stats.error_rate:.1f}%")
        content.write("")
        content.write(f"[green]2xx: {self.stats.status_2xx:,}[/]")
        content.write(f"[cyan]3xx: {self.stats.status_3xx:,}[/]")
        content.write(f"[yellow]4xx: {self.stats.status_4xx:,}[/]")
        content.write(f"[red]5xx: {self.stats.status_5xx:,}[/]")

        if self.stats.time_range:
            start, end = self.stats.time_range
            content.write("")
            content.write("[bold green]Time Range:[/]")
            content.write(
                f"  {start.strftime('%H:%M:%S')} - {end.strftime('%H:%M:%S')}"
            )

    def _update_alerts(self, content: RichLog) -> None:
        """Update alerts view - show ALL alerts without paging."""
        content.clear()
        alerts = self.security_rules.get_all_alerts()

        if not alerts:
            content.write("[bold green]No security alerts detected[/]")
            return

        # Get summary
        high_count = len([a for a in alerts if a.severity == "high"])
        medium_count = len([a for a in alerts if a.severity == "medium"])
        low_count = len([a for a in alerts if a.severity == "low"])

        total_alerts = len(alerts)

        content.write("[bold red]SECURITY ALERTS[/]")
        content.write(
            f"[yellow]Total: {total_alerts} | High: {high_count} | Medium: {medium_count} | Low: {low_count}[/]"
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

        # Render charts
        chart_text = render_charts_dashboard(
            hourly_traffic=hourly_data,
            error_rates=error_rates,
            status_2xx=self.stats.status_2xx,
            status_3xx=self.stats.status_3xx,
            status_4xx=self.stats.status_4xx,
            status_5xx=self.stats.status_5xx,
        )

        # Write each line
        for line in chart_text.split("\n"):
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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle tab button presses."""
        if event.button.id == "btn-stats":
            self.current_view = "stats"
            self.query_one("#btn-stats", Button).variant = "primary"
            self.query_one("#btn-alerts", Button).variant = "default"
            self.query_one("#btn-charts", Button).variant = "default"
            self._update_info()
        elif event.button.id == "btn-alerts":
            self.current_view = "alerts"
            self.query_one("#btn-stats", Button).variant = "default"
            self.query_one("#btn-alerts", Button).variant = "primary"
            self.query_one("#btn-charts", Button).variant = "default"
            self._update_info()
        elif event.button.id == "btn-charts":
            self.current_view = "charts"
            self.query_one("#btn-stats", Button).variant = "default"
            self.query_one("#btn-alerts", Button).variant = "default"
            self.query_one("#btn-charts", Button).variant = "primary"
            self._update_info()

    def action_open_filter(self) -> None:
        """Open filter modal."""

        def handle_filters(filters: Optional[FilterState]) -> None:
            if filters is not None:
                self.filter_engine.filters = filters
                self._apply_filters()

        self.push_screen(FilterModal(self.filter_engine.filters), handle_filters)

    def action_clear_filters(self) -> None:
        """Clear filters."""
        self.filter_engine.clear_filters()
        self._apply_filters()
        self.notify("Filters cleared")

    def action_toggle_info(self) -> None:
        """Toggle info panel visibility."""
        self.show_stats = not self.show_stats
        info_panel = self.query_one("#info-panel")
        info_panel.set_class(not self.show_stats, "hidden")

    def action_toggle_live(self) -> None:
        """Toggle live mode on/off."""
        if not self.log_path:
            self.notify("No log file loaded", severity="warning")
            return
        self.live_mode = not self.live_mode

    def action_show_alerts(self) -> None:
        """Switch to alerts view and focus."""
        self.current_view = "alerts"
        # Update button states
        stats_btn = self.query_one("#btn-stats", Button)
        alerts_btn = self.query_one("#btn-alerts", Button)
        charts_btn = self.query_one("#btn-charts", Button)
        stats_btn.variant = "default"
        alerts_btn.variant = "primary"
        charts_btn.variant = "default"
        self._update_info()
        self.notify("Alerts view - press j/k to scroll")

    def action_show_charts(self) -> None:
        """Switch to charts view."""
        self.current_view = "charts"
        # Update button states
        stats_btn = self.query_one("#btn-stats", Button)
        alerts_btn = self.query_one("#btn-alerts", Button)
        charts_btn = self.query_one("#btn-charts", Button)
        stats_btn.variant = "default"
        alerts_btn.variant = "default"
        charts_btn.variant = "primary"
        self._update_info()
        self.notify("Charts view - traffic visualization")

    def action_reload(self) -> None:
        """Reload log files."""
        if self.log_paths:
            self._load_log_files()

    def action_open_config(self) -> None:
        """Open config file info."""
        from pathlib import Path
        import os
        
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
            if self.log_path:
                base_name = Path(self.log_path).stem
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
                    self.notify(f"✅ Both formats exported!")

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
    """Entry point."""
    # Support multiple log files
    log_paths = sys.argv[1:] if len(sys.argv) > 1 else []
    app = LogInvestigatorApp(log_paths)
    app.run()


def make_app() -> LogInvestigatorApp:
    """Create app instance for textual run."""
    # For textual run without arguments
    return LogInvestigatorApp("sample_logs/access.log")


if __name__ == "__main__":
    main()
