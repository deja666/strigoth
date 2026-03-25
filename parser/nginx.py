import re
from datetime import datetime
from typing import Optional

from core.models import LogEntry

NGINX_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<agent>[^"]*)"'
)


def parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single nginx access log line.
    
    Args:
        line: Raw log line string
        
    Returns:
        LogEntry if parsing succeeds, None otherwise
    """
    match = NGINX_LOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()
    
    try:
        time = datetime.strptime(
            data["time"], "%d/%b/%Y:%H:%M:%S %z"
        )
        status = int(data["status"])
        size = int(data["size"])
    except (ValueError, KeyError):
        return None

    return LogEntry(
        ip=data["ip"],
        time=time,
        method=data["method"],
        path=data["path"],
        status=status,
        size=size,
        referer=data["referer"],
        agent=data["agent"],
        raw=line.strip()
    )


def parse_file(filepath: str):
    """
    Generator that parses a log file line by line.
    
    Args:
        filepath: Path to the nginx access log file
        
    Yields:
        LogEntry objects for each successfully parsed line
    """
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            entry = parse_line(line)
            if entry:
                yield entry
