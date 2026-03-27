"""Apache access log parser.

This module provides functions for parsing Apache access log lines
supporting both Combined and Common log formats.
"""
import re
from datetime import datetime
from typing import Generator, Optional

from core.models import LogEntry

# Apache Combined Log Format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "..." "..."
APACHE_COMBINED_PATTERN = re.compile(
    r"^(?P<ip>\S+) "  # IP address
    r"\S+ "  # identd (usually -)
    r"\S+ "  # userid (usually -)
    r"\[(?P<time>[^\]]+)\] "  # timestamp
    r'"(?P<method>\S+) '  # HTTP method
    r"(?P<path>\S+) "  # Request path
    r'\S+" '  # HTTP version
    r"(?P<status>\d{3}) "  # Status code
    r"(?P<size>\S+) "  # Response size
    r'"(?P<referer>[^"]*)" '  # Referer
    r'"(?P<agent>[^"]*)"'  # User agent
)

# Apache Common Log Format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
APACHE_COMMON_PATTERN = re.compile(
    r"^(?P<ip>\S+) "  # IP address
    r"\S+ "  # identd (usually -)
    r"\S+ "  # userid (usually -)
    r"\[(?P<time>[^\]]+)\] "  # timestamp
    r'"(?P<method>\S+) '  # HTTP method
    r"(?P<path>\S+) "  # Request path
    r'\S+" '  # HTTP version
    r"(?P<status>\d{3}) "  # Status code
    r"(?P<size>\S+)"  # Response size
)


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse a single Apache access log line.
    
    Supports both Combined and Common log formats.

    Args:
        line: Raw log line string

    Returns:
        LogEntry if parsing succeeds, None otherwise
    """
    # Try Combined format first
    match = APACHE_COMBINED_PATTERN.search(line)
    if not match:
        # Try Common format
        match = APACHE_COMMON_PATTERN.search(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        # Parse Apache timestamp format: 10/Oct/2000:13:55:36 -0700
        time = datetime.strptime(data["time"], "%d/%b/%Y:%H:%M:%S %z")
        status = int(data["status"])

        # Handle size field (can be "-" for no content)
        size_str = data.get("size", "0")
        size = int(size_str) if size_str != "-" else 0

        # Get optional fields
        referer = data.get("referer", "-")
        agent = data.get("agent", "")

    except (ValueError, KeyError):
        return None

    return LogEntry(
        ip=data["ip"],
        time=time,
        method=data["method"],
        path=data["path"],
        status=status,
        size=size,
        referer=referer,
        agent=agent,
        raw=line.strip(),
    )


def parse_file(filepath: str) -> Generator[LogEntry, None, None]:
    """Generator that parses an Apache access log file line by line.
    
    Args:
        filepath: Path to the Apache access log file

    Yields:
        LogEntry objects for each successfully parsed line
    """
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            entry = parse_line(line)
            if entry:
                yield entry
