from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LogEntry:
    """Represents a single parsed log entry."""
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    size: int
    referer: str
    agent: str
    raw: str = ""
    source_file: str = ""  # Source file path for multi-log support
    source_label: str = ""  # Human-readable source label (e.g., "Server1")
