"""Log format auto-detection."""
import re
from typing import Optional, Callable, Type
from pathlib import Path

from core.models import LogEntry


# Regex patterns for format detection
NGINX_PATTERN = re.compile(
    r'^\S+ - - \[[^\]]+\] "\S+ \S+ \S+" \d{3} \d+ "[^"]*" "[^"]*"'
)

APACHE_COMBINED_PATTERN = re.compile(
    r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ \S+ \S+" \d{3} \S+ "[^"]*" "[^"]*"'
)

APACHE_COMMON_PATTERN = re.compile(
    r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ \S+ \S+" \d{3} \S+$'
)


class LogFormat:
    """Log format enumeration."""
    NGINX = "nginx"
    APACHE_COMBINED = "apache_combined"
    APACHE_COMMON = "apache_common"
    UNKNOWN = "unknown"


def detect_format(line: str) -> str:
    """
    Detect log format from a single line.
    
    Args:
        line: First line of log file
        
    Returns:
        Log format string
    """
    line = line.strip()
    
    if not line:
        return LogFormat.UNKNOWN
    
    # Try patterns in order of specificity
    if NGINX_PATTERN.match(line):
        return LogFormat.NGINX
    
    if APACHE_COMBINED_PATTERN.match(line):
        return LogFormat.APACHE_COMBINED
    
    if APACHE_COMMON_PATTERN.match(line):
        return LogFormat.APACHE_COMMON
    
    return LogFormat.UNKNOWN


def detect_file_format(filepath: str) -> str:
    """
    Detect log format from file.
    
    Reads first line and detects format.
    
    Args:
        filepath: Path to log file
        
    Returns:
        Log format string
    """
    path = Path(filepath)
    if not path.exists():
        return LogFormat.UNKNOWN
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            first_line = f.readline()
            return detect_format(first_line)
    except Exception:
        return LogFormat.UNKNOWN


def get_parser_for_format(format_type: str) -> Callable[[str], Optional[LogEntry]]:
    """
    Get parser function for log format.
    
    Args:
        format_type: Log format string
        
    Returns:
        Parser function
    """
    if format_type == LogFormat.APACHE_COMBINED or format_type == LogFormat.APACHE_COMMON:
        from parser.apache import parse_line
        return parse_line
    else:
        # Default to Nginx
        from parser.nginx import parse_line
        return parse_line


def parse_with_auto_detect(filepath: str):
    """
    Parse log file with auto-detected format.
    
    Args:
        filepath: Path to log file
        
    Yields:
        LogEntry objects
    """
    # Detect format
    format_type = detect_file_format(filepath)
    
    # Get appropriate parser
    parser = get_parser_for_format(format_type)
    
    # Parse file
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            entry = parser(line)
            if entry:
                yield entry
