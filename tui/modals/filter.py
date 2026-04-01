"""Filter modal dialog."""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from core.filter_engine import FilterState


class FilterModal(ModalScreen):
    """Modal dialog for setting log filters."""

    BINDINGS = [
        ("escape", "close", "Close"),
        ("enter", "apply", "Apply"),
    ]

    def __init__(self, current_filters: FilterState) -> None:
        """Initialize filter modal.
        
        Args:
            current_filters: Current filter state to populate fields
        """
        super().__init__()
        self.current_filters = current_filters

    def compose(self) -> ComposeResult:
        """Compose the modal content."""
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
            yield Input(value=self.current_filters.ip or "", id="filter-ip")
            yield Label("HTTP Method:")
            yield Input(value=self.current_filters.method or "", id="filter-method")
            yield Label("Path:")
            yield Input(value=self.current_filters.path or "", id="filter-path")
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
        """Handle button press events."""
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
        """Clear all filter fields."""
        for widget_id in [
            "filter-status",
            "filter-method",
            "filter-ip",
            "filter-path",
            "filter-source",
        ]:
            self.query_one(f"#{widget_id}", Input).value = ""

    def action_close(self) -> None:
        """Close modal without applying."""
        self.dismiss(None)

    def action_apply(self) -> None:
        """Apply filters and close modal."""
        self._apply_filters()
