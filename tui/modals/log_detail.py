"""Log entry detail modal dialog."""

import subprocess
from typing import Any, List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, ScrollableContainer
from textual.screen import ModalScreen
from textual.widgets import Static

from core.models import LogEntry


class LogDetailModal(ModalScreen):
    """Modal dialog for displaying detailed log entry information.

    This modal provides a read-only view of all log entry fields
    in a structured key-value format with proper color coding.
    """

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("n", "next_entry", "Next Entry"),
        ("p", "prev_entry", "Previous Entry"),
        ("c", "copy_ip", "Copy IP"),
        ("f", "filter_ip", "Filter IP"),
    ]

    def __init__(
        self,
        log_entry: LogEntry,
        entry_index: int = 0,
        filtered_entries: Optional[List[LogEntry]] = None,
    ) -> None:
        """Initialize modal with log entry.

        Args:
            log_entry: Log entry to display in the modal
            entry_index: Current entry index in filtered_entries list
            filtered_entries: List of filtered entries for navigation
        """
        super().__init__()
        self.log_entry = log_entry
        self.entry_index = entry_index
        self.filtered_entries = filtered_entries or []

    def compose(self) -> ComposeResult:
        """Compose the modal content."""
        with Container(id="log-detail-modal"):
            yield Static("LOG ENTRY DETAILS", id="modal-title")
            with ScrollableContainer(id="modal-content"):
                yield from self._render_fields()

    def _render_fields(self) -> ComposeResult:
        """Render log entry fields as key-value pairs.

        Yields:
            Static widgets containing formatted field data
        """
        # Entry counter
        total = len(self.filtered_entries)
        if total > 0:
            yield Static(
                f"[bold]Entry {self.entry_index + 1} of {total}[/]", id="entry-counter"
            )

        # Timestamp
        yield self._make_row(
            "Timestamp",
            self.log_entry.time.isoformat() if self.log_entry.time else "N/A",
        )

        # IP Address
        yield self._make_row("IP Address", self.log_entry.ip or "N/A")

        # HTTP Method
        yield self._make_row("Method", self.log_entry.method or "N/A", color="cyan")

        # Request Path
        yield self._make_row("Path", self.log_entry.path or "N/A")

        # Status Code
        status_color = self._get_status_color(self.log_entry.status)
        yield self._make_row("Status", str(self.log_entry.status), color=status_color)

        # Response Size
        size_str = f"{self.log_entry.size:,} bytes" if self.log_entry.size else "N/A"
        yield self._make_row("Size", size_str)

        # User Agent
        yield self._make_row("User Agent", self.log_entry.agent or "N/A")

        # Source File
        yield self._make_row("Source", self.log_entry.source_file or "N/A")

        # Related Entries (Quick Filter)
        if self.log_entry.ip and self.filtered_entries:
            related_count = (
                sum(1 for e in self.filtered_entries if e.ip == self.log_entry.ip) - 1
            )

            if related_count > 0:
                yield Static(
                    f"[bold cyan]{related_count} other entries[/] from {self.log_entry.ip} (Press [bold]f[/] to filter)",
                    id="related-entries",
                )

        # Raw Log Line
        yield Static(
            f"[bold]Raw Log:[/]\n[dim]{self.log_entry.raw or 'N/A'}[/dim]", id="raw-log"
        )

    def _make_row(self, label: str, value: str, color: Optional[str] = None) -> Static:
        """Create a labeled row widget using Rich Text for consistent colors.

        Args:
            label: Field label
            value: Field value
            color: Optional color for the value

        Returns:
            Static widget with formatted label and value
        """
        # Use Rich Text for consistent color rendering (same as DataTable)
        text = Text()
        text.append(f"{label}:\n", style="bold")

        if color:
            text.append(value, style=f"bold {color}")
        else:
            text.append(value)

        return Static(text)

    def _get_status_color(self, status_code: int) -> str:
        """Get color for HTTP status code.

        Args:
            status_code: HTTP status code

        Returns:
            Color string for the status code category
        """
        status_category = int(str(status_code)[0])
        color_map = {2: "green", 3: "red", 4: "yellow", 5: "purple"}
        return color_map.get(status_category, "white")

    def action_next_entry(self) -> None:
        """Navigate to next log entry."""
        if self.entry_index < len(self.filtered_entries) - 1:
            # Dismiss current modal and open next entry
            next_index = self.entry_index + 1
            next_entry = self.filtered_entries[next_index]

            # Dismiss with navigation info
            self.dismiss(
                {"action": "navigate", "entry": next_entry, "index": next_index}
            )
        else:
            self.notify("Already at last entry", timeout=1)

    def action_prev_entry(self) -> None:
        """Navigate to previous log entry."""
        if self.entry_index > 0:
            # Dismiss current modal and open previous entry
            prev_index = self.entry_index - 1
            prev_entry = self.filtered_entries[prev_index]

            # Dismiss with navigation info
            self.dismiss(
                {"action": "navigate", "entry": prev_entry, "index": prev_index}
            )
        else:
            self.notify("Already at first entry", timeout=1)

    def action_copy_ip(self) -> None:
        """Copy IP address to system clipboard."""
        ip = self.log_entry.ip

        if not ip:
            self.notify("No IP address to copy", timeout=1)
            return

        try:
            # Cross-platform clipboard copy using subprocess
            self._copy_to_clipboard(ip)
            self.notify(f"IP copied to clipboard: {ip}", timeout=2)
        except Exception:
            self.notify("Failed to copy IP to clipboard", timeout=2, severity="error")

    def action_filter_ip(self) -> None:
        """Filter main table by this entry's IP."""
        if self.log_entry.ip:
            self.dismiss({"action": "filter_ip", "ip": self.log_entry.ip})
        else:
            self.notify("No IP address to filter", timeout=1)

    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        """Copy text to system clipboard (cross-platform).

        Args:
            text: Text to copy to clipboard
        """
        import sys

        # Try platform-specific methods
        if sys.platform == "win32":
            # Windows
            subprocess.run(["clip"], input=text.encode("utf-8"), check=True)
        elif sys.platform == "darwin":
            # macOS
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
        else:
            # Linux (try xclip, then xsel)
            try:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text.encode("utf-8"),
                    check=True,
                )
            except FileNotFoundError:
                try:
                    subprocess.run(
                        ["xsel", "--clipboard", "--input"],
                        input=text.encode("utf-8"),
                        check=True,
                    )
                except FileNotFoundError:
                    raise RuntimeError(
                        "No clipboard utility found. Install xclip or xsel."
                    )
