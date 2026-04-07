"""Preset Manager for saving and loading filter configurations."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.filter_engine import FilterState


class PresetManager:
    """Manages saving and loading of filter presets.

    Presets are stored in a JSON file (presets.json) in the application root.
    """

    PRESETS_FILE = "presets.json"

    def __init__(self) -> None:
        """Initialize the PresetManager."""
        self._presets: Dict[str, Dict[str, Any]] = {}
        self._load_presets()

    def _get_file_path(self) -> Path:
        """Get the path to the presets file."""
        # Try to find the file in the project root relative to this file
        root_dir = Path(__file__).resolve().parent.parent
        return root_dir / self.PRESETS_FILE

    def _load_presets(self) -> None:
        """Load presets from the JSON file."""
        presets_file = self._get_file_path()
        if presets_file.exists():
            try:
                with open(presets_file, "r", encoding="utf-8") as f:
                    self._presets = json.load(f)
            except (json.JSONDecodeError, IOError):
                # If file is corrupt, start fresh
                self._presets = {}
        else:
            self._presets = {}

    def _save_presets(self) -> None:
        """Save current presets to the JSON file."""
        presets_file = self._get_file_path()
        try:
            with open(presets_file, "w", encoding="utf-8") as f:
                json.dump(self._presets, f, indent=4)
        except IOError as e:
            raise RuntimeError(f"Failed to save presets: {e}")

    def get_all_presets(self) -> Dict[str, Dict[str, Any]]:
        """Get a copy of all saved presets.

        Returns:
            Dictionary mapping preset name to filter configuration.
        """
        return self._presets.copy()

    def save_preset(self, name: str, filter_state: FilterState) -> None:
        """Save a new or update an existing preset.

        Args:
            name: Name of the preset.
            filter_state: The FilterState object to save.
        """
        if not name or not name.strip():
            raise ValueError("Preset name cannot be empty.")

        # Serialize FilterState to dict
        preset_data = {
            "status": filter_state.status,
            "method": filter_state.method,
            "ip": filter_state.ip,
            "path": filter_state.path,
            "source": filter_state.source,
            "search": filter_state.search,
        }

        self._presets[name.strip()] = preset_data
        self._save_presets()

    def delete_preset(self, name: str) -> None:
        """Delete a saved preset.

        Args:
            name: Name of the preset to delete.
        """
        if name in self._presets:
            del self._presets[name]
            self._save_presets()

    def load_preset(self, name: str) -> Optional[FilterState]:
        """Load a specific preset and return a FilterState.

        Args:
            name: Name of the preset to load.

        Returns:
            FilterState object if found, None otherwise.
        """
        if name in self._presets:
            data = self._presets[name]
            return FilterState(
                status=data.get("status"),
                method=data.get("method"),
                ip=data.get("ip"),
                path=data.get("path"),
                source=data.get("source"),
                search=data.get("search"),
            )
        return None
