"""Log entry detail modal dialog."""

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from core.models import LogEntry
from rich.text import Text


class LogDetailModal(ModalScreen):
    """Modal dialog for displaying detailed log entry information.
    
    This modal provides a read-only view of all log entry fields
    in a structured key-value format with proper color coding.
    """

    BINDINGS = [
        ("escape", "dismiss", "Close"),
    ]

    def __init__(self, log_entry: LogEntry) -> None:
        """Initialize modal with log entry.
        
        Args:
            log_entry: Log entry to display in the modal
        """
        super().__init__()
        self.log_entry = log_entry

    def compose(self) -> ComposeResult:
        """Compose the modal content."""
        with Container(id="log-detail-modal"):
            yield Static("LOG ENTRY DETAILS", id="modal-title")
            with Vertical(id="modal-content"):
                yield from self._render_fields()

    def _render_fields(self) -> ComposeResult:
        """Render log entry fields as key-value pairs.
        
        Yields:
            Static widgets containing formatted field data
        """
        # Timestamp
        yield self._make_row(
            "Timestamp",
            self.log_entry.time.isoformat() if self.log_entry.time else "N/A"
        )

        # IP Address
        yield self._make_row("IP Address", self.log_entry.ip or "N/A")

        # HTTP Method
        yield self._make_row(
            "Method",
            self.log_entry.method or "N/A",
            color="cyan"
        )

        # Request Path
        yield self._make_row("Path", self.log_entry.path or "N/A")

        # Status Code
        status_color = self._get_status_color(self.log_entry.status)
        yield self._make_row(
            "Status",
            str(self.log_entry.status),
            color=status_color
        )

        # Response Size
        size_str = (
            f"{self.log_entry.size:,} bytes"
            if self.log_entry.size
            else "N/A"
        )
        yield self._make_row("Size", size_str)

        # User Agent
        yield self._make_row(
            "User Agent",
            self.log_entry.agent or "N/A"
        )

        # Source File
        yield self._make_row(
            "Source",
            self.log_entry.source_file or "N/A"
        )

        # Raw Log Line
        yield Static(
            f"[bold]Raw Log:[/]\n[dim]{self.log_entry.raw or 'N/A'}[/dim]",
            id="raw-log"
        )

    def _make_row(
        self,
        label: str,
        value: str,
        color: str = None
    ) -> Static:
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
        color_map = {
            2: "green",
            3: "red",
            4: "yellow",
            5: "purple"
        }
        return color_map.get(status_category, "white")
