"""Log file loader with streaming support."""
from typing import List, Generator, Optional
from pathlib import Path

from core.models import LogEntry
from parser.nginx import parse_line


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
            
    def load(self, filepath: Optional[str] = None) -> List[LogEntry]:
        """
        Load all log entries from a file into memory.
        
        Args:
            filepath: Path to the nginx access log file
            
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
            
        entries = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = parse_line(line)
                if entry:
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
