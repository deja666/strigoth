from dataclasses import dataclass
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
