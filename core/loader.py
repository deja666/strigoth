"""Log file loader with streaming and multi-file support."""
from typing import List, Generator, Optional, Tuple, Dict
from pathlib import Path
from dataclasses import dataclass

from core.models import LogEntry
from parser.nginx import parse_line as parse_nginx_line
from parser.apache import parse_line as parse_apache_line
from parser.detector import detect_file_format, LogFormat


@dataclass
class LoadedFile:
    """Information about a loaded log file."""
    path: Path
    label: str
    entry_count: int
    enabled: bool = True


class LogLoader:
    """
    Loader for nginx access log files.

    Supports both streaming (generator-based) and
    batch loading of log entries.
    """

    def __init__(self, filepath: Optional[str] = None) -> None:
        """
        Initialize the log loader.

        Args:
            filepath: Path to the nginx access log file
        """
        self.filepath: Optional[Path] = None
        if filepath:
            self.filepath = Path(filepath)

    def load(self, filepath: Optional[str] = None, source_label: str = "") -> List[LogEntry]:
        """
        Load all log entries from a file into memory.
        
        Auto-detects log format (Nginx or Apache).

        Args:
            filepath: Path to the nginx access log file
            source_label: Optional label for the source file

        Returns:
            List of all parsed log entries

        Raises:
            FileNotFoundError: If the log file doesn't exist
            ValueError: If no filepath is provided
        """
        path = Path(filepath) if filepath else self.filepath

        if not path:
            raise ValueError("No log file path specified")

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        # Auto-detect format
        format_type = detect_file_format(str(path))
        
        # Select parser based on format
        if format_type in [LogFormat.APACHE_COMBINED, LogFormat.APACHE_COMMON]:
            parse_line = parse_apache_line
        else:
            parse_line = parse_nginx_line  # Default to nginx

        entries = []
        label = source_label or path.stem
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = parse_line(line)
                if entry:
                    entry.source_file = str(path)
                    entry.source_label = label
                    entry.raw = line.strip()
                    entries.append(entry)

        return entries

    def stream(self, filepath: Optional[str] = None) -> Generator[LogEntry, None, None]:
        """
        Stream log entries from a file (memory-efficient).

        Args:
            filepath: Path to the nginx access log file

        Yields:
            Parsed LogEntry objects one at a time

        Raises:
            FileNotFoundError: If the log file doesn't exist
            ValueError: If no filepath is provided
        """
        path = Path(filepath) if filepath else self.filepath

        if not path:
            raise ValueError("No log file path specified")

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = parse_line(line)
                if entry:
                    yield entry

    def read_new_lines(self, last_position: int) -> Tuple[List[LogEntry], int]:
        """
        Read new lines from file starting at last_position.

        Args:
            last_position: Byte position to start reading from

        Returns:
            Tuple of (new_entries, new_position)

        Raises:
            FileNotFoundError: If the log file doesn't exist
        """
        if not self.filepath or not self.filepath.exists():
            return [], last_position

        current_size = self.filepath.stat().st_size

        # File was truncated or rotated, reset position
        if current_size < last_position:
            last_position = 0

        # No new data
        if current_size == last_position:
            return [], last_position

        new_entries = []
        with open(self.filepath, "r", encoding="utf-8") as f:
            f.seek(last_position)
            for line in f:
                entry = parse_line(line)
                if entry:
                    new_entries.append(entry)

        new_position = f.tell()
        return new_entries, new_position

    def count(self, filepath: Optional[str] = None) -> int:
        """
        Count the number of parseable lines in a log file.

        Args:
            filepath: Path to the nginx access log file

        Returns:
            Number of parseable log entries

        Raises:
            FileNotFoundError: If the log file doesn't exist
            ValueError: If no filepath is provided
        """
        path = Path(filepath) if filepath else self.filepath

        if not path:
            raise ValueError("No log file path specified")

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if parse_line(line):
                    count += 1

        return count

    def exists(self) -> bool:
        """
        Check if the configured log file exists.

        Returns:
            True if the file exists, False otherwise
        """
        if not self.filepath:
            return False
        return self.filepath.exists()

    def get_size(self) -> int:
        """
        Get the size of the log file in bytes.

        Returns:
            File size in bytes

        Raises:
            ValueError: If no filepath is configured
        """
        if not self.filepath:
            raise ValueError("No log file path configured")
        return self.filepath.stat().st_size


class MultiLogLoader:
    """
    Loader for multiple nginx access log files.

    Supports loading, merging, and managing multiple log files
    with source tracking.
    """

    def __init__(self) -> None:
        """Initialize the multi-log loader."""
        self.loaded_files: Dict[str, LoadedFile] = {}
        self.all_entries: List[LogEntry] = []

    def load_files(self, filepaths: List[str], labels: Optional[List[str]] = None) -> List[LogEntry]:
        """
        Load multiple log files and merge entries.

        Args:
            filepaths: List of file paths to load
            labels: Optional list of labels for each file

        Returns:
            Merged list of all log entries, sorted by timestamp
        """
        self.loaded_files.clear()
        self.all_entries = []

        labels = labels or []

        for i, filepath in enumerate(filepaths):
            path = Path(filepath)
            if not path.exists():
                continue

            label = labels[i] if i < len(labels) else path.stem
            
            # Create loader with filepath set
            loader = LogLoader(filepath)
            entries = loader.load(filepath, label)

            self.loaded_files[str(path)] = LoadedFile(
                path=path,
                label=label,
                entry_count=len(entries),
            )

            self.all_entries.extend(entries)

        # Sort by timestamp
        self.all_entries.sort(key=lambda e: e.time if e.time else datetime.min)

        return self.all_entries

    def add_file(self, filepath: str, label: Optional[str] = None) -> List[LogEntry]:
        """
        Add a single log file to existing entries.

        Args:
            filepath: Path to the log file
            label: Optional label for the file

        Returns:
            New entries from the added file
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        label = label or path.stem
        loader = LogLoader(filepath)
        entries = loader.load(filepath, label)

        self.loaded_files[str(path)] = LoadedFile(
            path=path,
            label=label,
            entry_count=len(entries),
        )

        self.all_entries.extend(entries)
        self.all_entries.sort(key=lambda e: e.time if e.time else datetime.min)

        return entries

    def remove_file(self, filepath: str) -> None:
        """
        Remove a log file and its entries.

        Args:
            filepath: Path to the file to remove
        """
        path_str = str(Path(filepath))
        if path_str not in self.loaded_files:
            return

        label = self.loaded_files[path_str].label

        # Remove entries from this file
        self.all_entries = [
            e for e in self.all_entries if e.source_file != path_str
        ]

        # Remove file record
        del self.loaded_files[path_str]

    def get_entries_by_source(self, filepath: str) -> List[LogEntry]:
        """
        Get entries from a specific source file.

        Args:
            filepath: Path to the source file

        Returns:
            List of entries from that file
        """
        path_str = str(Path(filepath))
        return [e for e in self.all_entries if e.source_file == path_str]

    def get_all_entries(self) -> List[LogEntry]:
        """
        Get all merged log entries.

        Returns:
            List of all entries, sorted by timestamp
        """
        return self.all_entries

    def get_file_stats(self) -> List[LoadedFile]:
        """
        Get statistics for all loaded files.

        Returns:
            List of LoadedFile objects
        """
        return list(self.loaded_files.values())

    def get_total_count(self) -> int:
        """
        Get total number of entries across all files.

        Returns:
            Total entry count
        """
        return len(self.all_entries)

    def get_file_count(self) -> int:
        """
        Get number of loaded files.

        Returns:
            Number of files
        """
        return len(self.loaded_files)
