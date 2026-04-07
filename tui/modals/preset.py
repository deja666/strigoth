"""Preset Manager Modal for saving and loading filter configurations."""

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Static

from core.filter_engine import FilterState
from core.presets import PresetManager


class PresetModal(ModalScreen):
    """Modal dialog for managing filter presets."""

    BINDINGS = [
        ("escape", "close", "Close"),
        ("s", "save_preset", "Save"),
        ("l", "load_preset", "Load"),
        ("d", "delete_preset", "Delete"),
    ]

    def __init__(self, current_filters: FilterState) -> None:
        """Initialize preset modal.

        Args:
            current_filters: The current filter state to be saved.
        """
        super().__init__()
        self.current_filters = current_filters
        self.preset_manager = PresetManager()
        self.selected_preset_name: str = ""

    def compose(self) -> ComposeResult:
        """Compose the modal content."""
        with Container(id="preset-modal"):
            yield Static("FILTER PRESETS", id="preset-modal-title")
            
            with Horizontal(id="preset-input-container"):
                yield Input(placeholder="Enter name for new preset...", id="preset-name-input")
                yield Button("Save", id="btn-save", variant="success")
            
            with Vertical(id="preset-list-container"):
                yield DataTable(id="preset-table", cursor_type="row")
            
            with Horizontal(id="preset-modal-buttons"):
                yield Button("Load Selected", id="btn-load", variant="primary")
                yield Button("Delete Selected", id="btn-delete", variant="warning")
                yield Button("Cancel", id="btn-cancel", variant="default")

    def on_mount(self) -> None:
        """Initialize table on mount."""
        table = self.query_one("#preset-table", DataTable)
        table.add_columns("Preset Name", "Details")
        table.zebra_stripes = True
        self._load_preset_list()

    def _load_preset_list(self) -> None:
        """Load presets into the DataTable."""
        table = self.query_one("#preset-table", DataTable)
        table.clear()
        
        presets = self.preset_manager.get_all_presets()
        for name, data in presets.items():
            # Create a summary string
            details = []
            if data.get("status"): details.append(f"Status: {data['status']}")
            if data.get("ip"): details.append(f"IP: {data['ip']}")
            if data.get("method"): details.append(f"Method: {data['method']}")
            if data.get("path"): details.append(f"Path: {data['path']}")
            if data.get("source"): details.append(f"Source: {data['source']}")
            if data.get("search"): details.append(f"Search: {data['search']}")
            
            detail_str = " | ".join(details) if details else "No filters"
            table.add_row(name, detail_str, key=name)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection."""
        self.selected_preset_name = str(event.row_key.value)

    def _save_preset(self) -> None:
        """Save current filters as a preset."""
        input_widget = self.query_one("#preset-name-input", Input)
        name = input_widget.value.strip()
        
        if not name:
            self.notify("Please enter a name for the preset.", severity="warning")
            input_widget.focus()
            return

        try:
            self.preset_manager.save_preset(name, self.current_filters)
            self.notify(f"Preset '{name}' saved successfully.")
            input_widget.value = ""
            self._load_preset_list()
        except Exception as e:
            self.notify(f"Error saving preset: {e}", severity="error")

    def _load_preset(self) -> None:
        """Load the selected preset."""
        if not self.selected_preset_name:
            self.notify("Please select a preset to load.", severity="warning")
            return

        filter_state = self.preset_manager.load_preset(self.selected_preset_name)
        if filter_state:
            self.dismiss({"action": "load", "filter": filter_state})

    def _delete_preset(self) -> None:
        """Delete the selected preset."""
        if not self.selected_preset_name:
            self.notify("Please select a preset to delete.", severity="warning")
            return

        try:
            self.preset_manager.delete_preset(self.selected_preset_name)
            self.notify(f"Preset '{self.selected_preset_name}' deleted.")
            self.selected_preset_name = ""
            self._load_preset_list()
        except Exception as e:
            self.notify(f"Error deleting preset: {e}", severity="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        button_id = event.button.id
        if button_id == "btn-save":
            self._save_preset()
        elif button_id == "btn-load":
            self._load_preset()
        elif button_id == "btn-delete":
            self._delete_preset()
        elif button_id == "btn-cancel":
            self.dismiss(None)

    def action_close(self) -> None:
        """Close the modal."""
        self.dismiss(None)

    def action_save_preset(self) -> None:
        """Keyboard shortcut for save."""
        self._save_preset()

    def action_load_preset(self) -> None:
        """Keyboard shortcut for load."""
        self._load_preset()

    def action_delete_preset(self) -> None:
        """Keyboard shortcut for delete."""
        self._delete_preset()
