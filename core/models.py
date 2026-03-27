"""Data models for log entries and related structures."""
from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEntry:
    """Represents a single parsed log entry from web server access logs.
    
    Attributes:
        ip: Client IP address
        time: Request timestamp
        method: HTTP method (GET, POST, etc.)
        path: Requested URL path
        status: HTTP status code
        size: Response size in bytes
        referer: HTTP referer header
        agent: User agent string
        raw: Original raw log line
        source_file: Source file path for multi-log support
        source_label: Human-readable source label (e.g., "Server1")
    """
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    size: int
    referer: str
    agent: str
    raw: str = ""
    source_file: str = ""
    source_label: str = ""
