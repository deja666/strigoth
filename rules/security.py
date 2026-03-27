"""Security rules for anomaly detection in log entries.

This module provides a rule-based security anomaly detection engine that
identifies suspicious patterns in web server access logs, including brute
force attacks, sensitive path access, scanning behavior, and high request rates.
All rules are configurable via YAML configuration.
"""
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from core.config import Config, get_config
from core.models import LogEntry


@dataclass
class Alert:
    """Represents a security alert.
    
    Attributes:
        rule: Name of the rule that triggered the alert
        severity: Alert severity level (high, medium, low)
        message: Human-readable alert message
        ip: IP address associated with the alert
        path: Request path associated with the alert
        count: Number of occurrences
        first_seen: First occurrence timestamp
        last_seen: Last occurrence timestamp
    """
    rule: str
    severity: str
    message: str
    ip: Optional[str] = None
    path: Optional[str] = None
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class SecurityRules:
    """Rule-based security anomaly detection engine.
    
    Uses YAML configuration for customizable thresholds.
    
    Detects suspicious patterns in log entries including:
    - Brute force attempts (excessive 401 responses)
    - Sensitive path access attempts
    - Scanning behavior (many unique paths from same IP)
    - High request rates
    
    Attributes:
        config: Configuration object
        alerts: List of triggered alerts
        failed_logins: Failed login tracking by IP
        path_access: Path access tracking by IP
        request_times: Request time tracking by IP
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        """Initialize security rules.
        
        Args:
            config: Optional configuration object (uses global config if None)
        """
        self.config = config or get_config()
        self.alerts: List[Alert] = []
        self.failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        self.path_access: Dict[str, Dict[str, List[datetime]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.request_times: Dict[str, List[datetime]] = defaultdict(list)

    def reset(self) -> None:
        """Reset all tracking data and alerts."""
        self.alerts = []
        self.failed_logins.clear()
        self.path_access.clear()
        self.request_times.clear()

    def check(self, entry: LogEntry) -> List[Alert]:
        """Check a log entry against all security rules.
        
        Args:
            entry: Log entry to check

        Returns:
            List of triggered alerts
        """
        alerts: List[Alert] = []

        # Check brute force (401 responses)
        alerts.extend(self._check_brute_force(entry))

        # Check sensitive path access
        alerts.extend(self._check_sensitive_path(entry))

        # Check scanning behavior
        alerts.extend(self._check_scanning(entry))

        # Check high request rate
        alerts.extend(self._check_high_rate(entry))

        self.alerts.extend(alerts)
        return alerts

    def _check_brute_force(self, entry: LogEntry) -> List[Alert]:
        """Check for brute force login attempts.
        
        Detects excessive 401 responses from a single IP.
        
        Args:
            entry: Log entry to check
            
        Returns:
            List of triggered alerts
        """
        alerts: List[Alert] = []

        # Check if rule is enabled
        if not self.config.brute_force.enabled:
            return alerts

        if entry.status == 401:
            self.failed_logins[entry.ip].append(entry.time)

            # Clean old entries outside time window
            window = timedelta(seconds=self.config.brute_force.time_window)
            cutoff = entry.time - window
            self.failed_logins[entry.ip] = [
                t for t in self.failed_logins[entry.ip]
                if t > cutoff
            ]

            # Check if threshold exceeded
            recent_count = len(self.failed_logins[entry.ip])
            if recent_count >= self.config.brute_force.threshold:
                alerts.append(Alert(
                    rule="brute_force",
                    severity="high",
                    message=f"Possible brute force from {entry.ip} ({recent_count} failed attempts)",
                    ip=entry.ip,
                    count=recent_count,
                    first_seen=min(self.failed_logins[entry.ip]),
                    last_seen=max(self.failed_logins[entry.ip]),
                ))

        return alerts

    def _check_sensitive_path(self, entry: LogEntry) -> List[Alert]:
        """Check for access attempts to sensitive paths.
        
        Args:
            entry: Log entry to check
            
        Returns:
            List of triggered alerts
        """
        alerts: List[Alert] = []

        # Check if rule is enabled
        if not self.config.sensitive_paths:
            return alerts

        path_lower = entry.path.lower()

        for sensitive_path in self.config.sensitive_paths:
            if sensitive_path.lower() in path_lower:
                alerts.append(
                    Alert(
                        rule="sensitive_path",
                        severity="medium",
                        message=f"Sensitive path access: {entry.path} from {entry.ip}",
                        ip=entry.ip,
                        path=entry.path,
                    )
                )
                break

        return alerts

    def _check_scanning(self, entry: LogEntry) -> List[Alert]:
        """Check for scanning behavior.
        
        Detects IPs accessing many unique paths in short time.
        
        Args:
            entry: Log entry to check
            
        Returns:
            List of triggered alerts
        """
        alerts: List[Alert] = []

        # Check if rule is enabled
        if not self.config.scanning.enabled:
            return alerts

        # Track path access per IP
        self.path_access[entry.ip][entry.path].append(entry.time)

        # Clean old entries
        window = timedelta(seconds=self.config.scanning.time_window)
        cutoff = entry.time - window
        for ip in list(self.path_access.keys()):
            for path in list(self.path_access[ip].keys()):
                self.path_access[ip][path] = [
                    t for t in self.path_access[ip][path] if t > cutoff
                ]
                if not self.path_access[ip][path]:
                    del self.path_access[ip][path]
            if not self.path_access[ip]:
                del self.path_access[ip]

        # Count unique paths for this IP
        unique_paths = len(self.path_access[entry.ip])

        if unique_paths >= self.config.scanning.threshold:
            alerts.append(
                Alert(
                    rule="scanning",
                    severity="medium",
                    message=f"Possible scanning from {entry.ip} ({unique_paths} unique paths)",
                    ip=entry.ip,
                    count=unique_paths,
                )
            )

        return alerts

    def _check_high_rate(self, entry: LogEntry) -> List[Alert]:
        """Check for high request rate.
        
        Detects IPs with excessive requests in short time.
        
        Args:
            entry: Log entry to check
            
        Returns:
            List of triggered alerts
        """
        alerts: List[Alert] = []

        # Check if rule is enabled
        if not self.config.high_rate.enabled:
            return alerts

        self.request_times[entry.ip].append(entry.time)

        # Clean old entries
        window = timedelta(seconds=self.config.high_rate.time_window)
        cutoff = entry.time - window
        self.request_times[entry.ip] = [
            t for t in self.request_times[entry.ip] if t > cutoff
        ]

        request_count = len(self.request_times[entry.ip])

        if request_count >= self.config.high_rate.threshold:
            alerts.append(
                Alert(
                    rule="high_rate",
                    severity="low",
                    message=f"High request rate from {entry.ip} ({request_count} requests/min)",
                    ip=entry.ip,
                    count=request_count,
                )
            )

        return alerts

    def get_all_alerts(self) -> List[Alert]:
        """Get all triggered alerts.
        
        Returns:
            List of all alerts
        """
        return self.alerts

    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """Get alerts filtered by severity level.
        
        Args:
            severity: Severity level (high, medium, low)

        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts if a.severity == severity]

    def get_alerts_by_ip(self, ip: str) -> List[Alert]:
        """Get alerts for a specific IP.
        
        Args:
            ip: IP address to filter by

        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts if a.ip == ip]

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of security alerts.
        
        Returns:
            Dictionary with alert counts by severity
        """
        return {
            "total": len(self.alerts),
            "high": len(self.get_alerts_by_severity("high")),
            "medium": len(self.get_alerts_by_severity("medium")),
            "low": len(self.get_alerts_by_severity("low")),
        }
