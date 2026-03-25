"""
Strigoth Log Investigator TUI - Clean Professional Design
No emojis, no scrollbars issues, working colors.
"""
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import (
    Header,
    Footer,
    Static,
    Label,
    Input,
    Button,
    DataTable,
    Placeholder,
)
from textual.containers import Horizontal, Vertical, Container, VerticalScroll
from textual.color import Color
from rich.text import Text
from textual.reactive import reactive
from textual.screen import ModalScreen

from core.models import LogEntry
from core.loader import LogLoader
from core.stats import StatsEngine
from core.filter_engine import FilterEngine, FilterState
from rules.security import SecurityRules, Alert
from export.report import export_markdown


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
                value=str(self.current_filters.status) if self.current_filters.status else "",
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
        status_input = self.query_one("#filter-status", Input).value
        method = self.query_one("#filter-method", Input).value
        ip = self.query_one("#filter-ip", Input).value
        path = self.query_one("#filter-path", Input).value

        filters = FilterState(
            status=int(status_input) if status_input else None,
            method=method.upper() if method else None,
            ip=ip if ip else None,
            path=path if path else None,
        )
        self.dismiss(filters)

    def _clear_filters(self) -> None:
        for widget_id in ["filter-status", "filter-method", "filter-ip", "filter-path"]:
            self.query_one(f"#{widget_id}", Input).value = ""

    def action_close(self) -> None:
        self.dismiss(None)

    def action_apply(self) -> None:
        self._apply_filters()


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
                "  TAB - Switch between panels\n"
                "\n"
                "OTHER:\n"
                "  r - Reload log\n"
                "  e - Export report\n"
                "  ? - Show this help\n"
                "  q - Quit\n"
                "\n"
                "[dim]Tip: Press TAB to focus on different panels,[/]\n"
                "[dim]then use j/k to scroll[/]",
                id="help-content"
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
        ("r", "reload", "Reload"),
        ("e", "export_report", "Export"),
        ("?", "show_help", "Help"),
        ("j", "scroll_down", "Down"),
        ("k", "scroll_up", "Up"),
        ("g", "go_top", "Top"),
        ("G", "go_bottom", "Bottom"),
    ]
    
    # State
    show_stats = reactive(True)
    current_view = reactive("stats")  # "stats" or "alerts"
    
    TITLE = "STRIGOTH LOG INVESTIGATOR"
    SUB_TITLE = "v1.0"
    
    def __init__(self, log_path: Optional[str] = None) -> None:
        super().__init__()
        self.log_path = log_path
        self.loader = LogLoader(log_path) if log_path else None
        self.entries: list[LogEntry] = []
        self.filtered_entries: list[LogEntry] = []
        self.filter_engine = FilterEngine()
        self.stats_engine = StatsEngine()
        self.security_rules = SecurityRules()
        self.stats = None
        
    def compose(self) -> ComposeResult:
        yield Header()
        
        # Filter display bar
        yield Static("No filters active", id="filter-display")
        
        # Main content - 2 panels
        with Horizontal(id="main-container"):
            # Left - Log viewer
            with Vertical(id="log-panel"):
                yield DataTable(id="log-table")
                
            # Right - Info panel (stats/alerts)
            with Vertical(id="info-panel"):
                # Tab buttons
                with Horizontal(id="info-tabs"):
                    yield Button("STATS", id="btn-stats", variant="primary")
                    yield Button("ALERTS", id="btn-alerts", variant="default")
                
                # Scrollable content using VerticalScroll
                with VerticalScroll(id="info-scroll"):
                    yield Static("", id="info-content")
        
        # Status bar
        yield Static("", id="status-bar")
        yield Footer()
        
    def on_mount(self) -> None:
        """Initialize."""
        self.title = "STRIGOTH LOG INVESTIGATOR"
        self.sub_title = "v1.0 | Clean Edition"
        
        # Setup DataTable
        table = self.query_one("#log-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns(
            "Time",
            "IP Address",
            "Method",
            "Path",
            "Status",
            "Size",
        )
        
        # Load data
        if self.log_path:
            self._load_log_file()
        else:
            self.notify("Usage: python -m tui.app <logfile>", severity="warning")
            
    def _load_log_file(self) -> None:
        """Load log file."""
        if not self.loader:
            return
            
        try:
            table = self.query_one("#log-table", DataTable)
            
            self.entries = self.loader.load()
            
            # Process security
            self.security_rules.reset()
            for entry in self.entries:
                self.security_rules.check(entry)
                
            # Stats
            self.stats_engine.load(self.entries)
            self.stats = self.stats_engine.compute()
            
            # Apply filters
            self._apply_filters()
            
            self.notify(f"Loaded {len(self.entries):,} entries")
            
        except FileNotFoundError:
            self.notify(f"File not found: {self.log_path}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")
            
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
        content = self.query_one("#info-content", Static)
        
        if self.current_view == "stats":
            self._update_stats(content)
        else:
            self._update_alerts(content)
            
        # Focus the scroll container when viewing alerts
        if self.current_view == "alerts":
            scroll = self.query_one("#info-scroll", VerticalScroll)
            scroll.focus()
            
    def _update_stats(self, content: Static) -> None:
        """Update stats view."""
        if not self.stats:
            return
            
        lines = [
            "[bold green]STATISTICS[/]",
            "",
            f"Total: {self.stats.total_requests:,}",
            f"Unique IPs: {self.stats.unique_ips:,}",
            f"Error Rate: {self.stats.error_rate:.1f}%",
            "",
            f"[green]2xx: {self.stats.status_2xx:,}[/]",
            f"[cyan]3xx: {self.stats.status_3xx:,}[/]",
            f"[yellow]4xx: {self.stats.status_4xx:,}[/]",
            f"[red]5xx: {self.stats.status_5xx:,}[/]",
        ]
        
        content.update("\n".join(lines))
        
    def _update_alerts(self, content: Static) -> None:
        """Update alerts view - show ALL alerts without paging."""
        alerts = self.security_rules.get_all_alerts()
        
        if not alerts:
            content.update("[bold green]No security alerts detected[/]")
            return
            
        # Get summary
        high_count = len([a for a in alerts if a.severity == "high"])
        medium_count = len([a for a in alerts if a.severity == "medium"])
        low_count = len([a for a in alerts if a.severity == "low"])
        
        total_alerts = len(alerts)
        
        lines = [
            f"[bold red]SECURITY ALERTS ({total_alerts} total)[/]",
            "",
            f"[yellow]High: {high_count} | Medium: {medium_count} | Low: {low_count}[/]",
            "",
            "[dim]Use J/K to scroll through alerts[/]",
            "",
        ]
        
        # Display ALL alerts
        for i, alert in enumerate(alerts, 1):
            color = "red" if alert.severity == "high" else "yellow" if alert.severity == "medium" else "green"
            lines.append(f"[bold]{i}. {alert.severity.upper()}[/] - {alert.message}")
            if alert.count > 1:
                lines.append(f"   [dim]Count: {alert.count}[/]")
            if alert.ip:
                lines.append(f"   [dim]IP: {alert.ip}[/]")
            lines.append("")
                
        content.update("\n".join(lines))
        
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
        
        status_bar.update(
            f"Showing {filtered:,} of {total:,} | "
            f"Errors: {error_count} ({error_rate:.1f}%) | "
            f"Alerts: {alerts_count}"
        )
        
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle tab button presses."""
        if event.button.id == "btn-stats":
            self.current_view = "stats"
            self.query_one("#btn-stats", Button).variant = "primary"
            self.query_one("#btn-alerts", Button).variant = "default"
            self._update_info()
        elif event.button.id == "btn-alerts":
            self.current_view = "alerts"
            self.query_one("#btn-alerts", Button).variant = "primary"
            self.query_one("#btn-stats", Button).variant = "default"
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
        
    def action_show_alerts(self) -> None:
        """Switch to alerts view and focus."""
        self.current_view = "alerts"
        # Update button states
        stats_btn = self.query_one("#btn-stats", Button)
        alerts_btn = self.query_one("#btn-alerts", Button)
        stats_btn.variant = "default"
        alerts_btn.variant = "primary"
        # Focus and update
        self._update_info()
        self.notify("Alerts view - press j/k to scroll")
        
    def action_reload(self) -> None:
        """Reload log file."""
        if self.log_path:
            self._load_log_file()
            
    def action_export_report(self) -> None:
        """Export report."""
        if not self.stats:
            self.notify("No data to export", severity="warning")
            return
            
        if self.log_path:
            base_name = Path(self.log_path).stem
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/{base_name}_report_{timestamp}.md"
        else:
            output_path = "reports/log_report.md"
            
        try:
            export_markdown(
                stats=self.stats,
                filters=self.filter_engine.get_active_filters(),
                alerts=self.security_rules.get_all_alerts(),
                output_path=output_path,
                entries=self.filtered_entries,
            )
            self.notify(f"Report exported: {output_path}")
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")
            
    def action_show_help(self) -> None:
        """Show help."""
        self.push_screen(HelpModal())
        
    def action_scroll_down(self) -> None:
        """Scroll down - check which widget has focus."""
        focused = self.focused
        if focused and hasattr(focused, 'id'):
            if focused.id == "info-scroll":
                # Scroll info panel
                focused.scroll_relative(y=5)
                return
        # Default: scroll log table
        table = self.query_one("#log-table", DataTable)
        table.scroll_relative(y=5)
        
    def action_scroll_up(self) -> None:
        """Scroll up - check which widget has focus."""
        focused = self.focused
        if focused and hasattr(focused, 'id'):
            if focused.id == "info-scroll":
                # Scroll info panel
                focused.scroll_relative(y=-5)
                return
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
    log_path = sys.argv[1] if len(sys.argv) > 1 else None
    app = LogInvestigatorApp(log_path)
    app.run()


if __name__ == "__main__":
    main()
