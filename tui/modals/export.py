"""Export format selection modal dialog."""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ExportModal(ModalScreen):
    """Modal dialog for selecting export format."""

    BINDINGS = [
        ("escape", "close", "Close"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the modal content."""
        with Container(id="export-modal"):
            yield Static("EXPORT REPORT", id="export-modal-title")
            yield Static("Select export format:", id="export-modal-label")
            with Horizontal(id="export-modal-buttons"):
                yield Button("📄 Markdown", id="export-md", variant="primary")
                yield Button("📋 JSON", id="export-json", variant="default")
                yield Button("Both", id="export-both", variant="default")
                yield Button("Cancel", id="export-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id in ["export-md", "export-json", "export-both"]:
            self.dismiss(event.button.id)
        elif event.button.id == "export-cancel":
            self.dismiss(None)

    def action_close(self) -> None:
        """Close modal without exporting."""
        self.dismiss(None)
