"""Statistics aggregation for log analysis."""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from core.models import LogEntry


@dataclass
class StatsSummary:
    """Summary statistics for log analysis."""
    total_requests: int = 0
    unique_ips: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    methods: Dict[str, int] = field(default_factory=dict)
    top_paths: List[tuple[str, int]] = field(default_factory=list)
    top_ips: List[tuple[str, int]] = field(default_factory=list)
    time_range: Optional[tuple[datetime, datetime]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "Total Requests": f"{self.total_requests:,}",
            "Unique IPs": f"{self.unique_ips:,}",
            "Error Rate": f"{self.error_rate:.1f}%",
            "2xx": f"{self.status_2xx:,}",
            "3xx": f"{self.status_3xx:,}",
            "4xx": f"{self.status_4xx:,}",
            "5xx": f"{self.status_5xx:,}",
        }


class StatsEngine:
    """
    Engine for computing statistics from log entries.
    
    Provides aggregated metrics for log analysis including
    request counts, error rates, and top contributors.
    """
    
    def __init__(self) -> None:
        self.entries: List[LogEntry] = []
        
    def load(self, entries: List[LogEntry]) -> None:
        """
        Load log entries for analysis.
        
        Args:
            entries: List of log entries to analyze
        """
        self.entries = entries
        
    def compute(self) -> StatsSummary:
        """
        Compute all statistics from loaded entries.
        
        Returns:
            StatsSummary with computed metrics
        """
        if not self.entries:
            return StatsSummary()
            
        # Basic counts
        total = len(self.entries)
        unique_ips = set(e.ip for e in self.entries)
        
        # Status code breakdown
        status_codes = Counter(e.status for e in self.entries)
        status_2xx = sum(v for k, v in status_codes.items() if 200 <= k < 300)
        status_3xx = sum(v for k, v in status_codes.items() if 300 <= k < 400)
        status_4xx = sum(v for k, v in status_codes.items() if 400 <= k < 500)
        status_5xx = sum(v for k, v in status_codes.items() if 500 <= k < 600)
        error_count = status_4xx + status_5xx
        
        # Methods
        methods = dict(Counter(e.method for e in self.entries))
        
        # Top paths
        path_counts = Counter(e.path for e in self.entries)
        top_paths = path_counts.most_common(10)
        
        # Top IPs
        ip_counts = Counter(e.ip for e in self.entries)
        top_ips = ip_counts.most_common(10)
        
        # Time range
        times = [e.time for e in self.entries if e.time]
        time_range = None
        if times:
            time_range = (min(times), max(times))
            
        return StatsSummary(
            total_requests=total,
            unique_ips=len(unique_ips),
            error_count=error_count,
            error_rate=(error_count / total * 100) if total > 0 else 0.0,
            status_2xx=status_2xx,
            status_3xx=status_3xx,
            status_4xx=status_4xx,
            status_5xx=status_5xx,
            methods=methods,
            top_paths=top_paths,
            top_ips=top_ips,
            time_range=time_range,
        )
        
    def get_status_distribution(self) -> Dict[int, int]:
        """
        Get distribution of status codes.
        
        Returns:
            Dictionary mapping status codes to counts
        """
        return dict(Counter(e.status for e in self.entries))
        
    def get_requests_by_ip(self, limit: int = 10) -> List[tuple[str, int]]:
        """
        Get top IPs by request count.
        
        Args:
            limit: Maximum number of IPs to return
            
        Returns:
            List of (IP, count) tuples
        """
        return Counter(e.ip for e in self.entries).most_common(limit)
        
    def get_requests_by_path(self, limit: int = 10) -> List[tuple[str, int]]:
        """
        Get top paths by request count.
        
        Args:
            limit: Maximum number of paths to return
            
        Returns:
            List of (path, count) tuples
        """
        return Counter(e.path for e in self.entries).most_common(limit)
        
    def get_requests_by_method(self) -> Dict[str, int]:
        """
        Get request count by HTTP method.
        
        Returns:
            Dictionary mapping methods to counts
        """
        return dict(Counter(e.method for e in self.entries))
        
    def get_error_entries(self) -> List[LogEntry]:
        """
        Get all entries with 4xx or 5xx status codes.
        
        Returns:
            List of error log entries
        """
        return [e for e in self.entries if e.status >= 400]
        
    def get_entries_by_status(self, status: int) -> List[LogEntry]:
        """
        Get entries with a specific status code.
        
        Args:
            status: Status code to filter by
            
        Returns:
            List of matching log entries
        """
        return [e for e in self.entries if e.status == status]
