"""Help modal dialog showing keyboard shortcuts."""

from textual.app import ComposeResult
from textual.containers import Container, ScrollableContainer
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class HelpModal(ModalScreen):
    """Modal dialog showing keyboard shortcuts."""

    BINDINGS = [
        ("escape", "close", "Close"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the modal content."""
        with Container(id="help-modal"):
            yield Static("KEYBOARD SHORTCUTS", id="help-modal-title")
            with ScrollableContainer(id="help-content"):
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
        """Handle button press events."""
        if event.button.id == "close":
            self.dismiss()

    def action_close(self) -> None:
        """Close modal."""
        self.dismiss()
