"""Filter engine for log entries."""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from core.models import LogEntry


@dataclass
class FilterState:
    """Represents the current filter state."""
    status: Optional[int] = None
    status_min: Optional[int] = None
    status_max: Optional[int] = None
    ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    search: Optional[str] = None
    source: Optional[str] = None  # Source file filter for multi-log support


class FilterEngine:
    """
    Engine for filtering log entries based on various criteria.
    
    Supports filtering by status code, IP address, HTTP method,
    path keyword, and full-text search.
    """
    
    def __init__(self) -> None:
        self.filters: FilterState = FilterState()
        
    def set_filter(self, name: str, value: Any) -> None:
        """
        Set a filter value by name.
        
        Args:
            name: Filter name (status, ip, method, path, search)
            value: Filter value to set
        """
        if hasattr(self.filters, name):
            setattr(self.filters, name, value)
            
    def clear_filters(self) -> None:
        """Clear all active filters."""
        self.filters = FilterState()
        
    def is_active(self) -> bool:
        """
        Check if any filters are currently active.

        Returns:
            True if at least one filter is set, False otherwise
        """
        return any([
            self.filters.status is not None,
            self.filters.status_min is not None,
            self.filters.status_max is not None,
            self.filters.ip is not None,
            self.filters.method is not None,
            self.filters.path is not None,
            self.filters.search is not None,
            self.filters.source is not None,  # Source filter!
        ])
        
    def apply(self, entries: List[LogEntry]) -> List[LogEntry]:
        """
        Apply all active filters to a list of log entries.

        Args:
            entries: List of log entries to filter

        Returns:
            Filtered list of log entries
        """
        if not self.is_active():
            return entries

        return [e for e in entries if self._matches(e)]
        
    def _matches(self, entry: LogEntry) -> bool:
        """
        Check if a log entry matches all active filters.

        Args:
            entry: Log entry to check

        Returns:
            True if entry matches all filters, False otherwise
        """
        # Status code filter (exact)
        if self.filters.status is not None:
            if entry.status != self.filters.status:
                return False

        # Status code range filter
        if self.filters.status_min is not None:
            if entry.status < self.filters.status_min:
                return False

        if self.filters.status_min is not None:
            if entry.status > self.filters.status_max:
                return False

        # IP address filter (substring match)
        if self.filters.ip is not None:
            if self.filters.ip.lower() not in entry.ip.lower():
                return False

        # HTTP method filter (exact match)
        if self.filters.method is not None:
            if entry.method.upper() != self.filters.method.upper():
                return False

        # Path filter (substring match)
        if self.filters.path is not None:
            if self.filters.path.lower() not in entry.path.lower():
                return False

        # Source file filter (substring match)
        if self.filters.source is not None:
            source_to_check = entry.source_label or entry.source_file or ""
            if self.filters.source.lower() not in source_to_check.lower():
                return False

        # Full-text search (searches in raw log line)
        if self.filters.search is not None:
            if self.filters.search.lower() not in entry.raw.lower():
                return False

        return True
        
    def get_active_filters(self) -> Dict[str, Any]:
        """
        Get a dictionary of all currently active filters.

        Returns:
            Dictionary mapping filter names to their values
        """
        result = {}
        for field_name in ['status', 'status_min', 'status_max', 'ip', 'method', 'path', 'search', 'source']:
            value = getattr(self.filters, field_name)
            if value is not None:
                result[field_name] = value
        return result
