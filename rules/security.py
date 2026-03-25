"""Security rules for anomaly detection in log entries."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timedelta

from core.models import LogEntry


@dataclass
class Alert:
    """Represents a security alert."""
    rule: str
    severity: str
    message: str
    ip: Optional[str] = None
    path: Optional[str] = None
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class RuleConfig:
    """Configuration for a security rule."""
    enabled: bool = True
    threshold: int = 10
    time_window: timedelta = field(default_factory=lambda: timedelta(minutes=1))


class SecurityRules:
    """
    Rule-based security anomaly detection engine.
    
    Detects suspicious patterns in log entries including:
    - Brute force attempts (excessive 401 responses)
    - Sensitive path access attempts
    - Scanning behavior (many unique paths from same IP)
    - High request rates
    """
    
    # Default thresholds
    FAILED_LOGIN_THRESHOLD = 10
    FAILED_LOGIN_WINDOW = timedelta(minutes=1)
    
    SCANNING_THRESHOLD = 20
    SCANNING_WINDOW = timedelta(minutes=5)
    
    HIGH_RATE_THRESHOLD = 100
    HIGH_RATE_WINDOW = timedelta(minutes=1)
    
    SENSITIVE_PATHS = [
        "/admin",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/pma",
        "/.env",
        "/.git",
        "/config",
        "/backup",
        "/.htaccess",
        "/wp-config.php",
        "/xmlrpc.php",
    ]
    
    def __init__(self) -> None:
        self.alerts: List[Alert] = []
        self.failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        self.path_access: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        self.request_times: Dict[str, List[datetime]] = defaultdict(list)
        self.config: Dict[str, RuleConfig] = {}
        
    def reset(self) -> None:
        """Reset all tracking data and alerts."""
        self.alerts = []
        self.failed_logins.clear()
        self.path_access.clear()
        self.request_times.clear()
        
    def check(self, entry: LogEntry) -> List[Alert]:
        """
        Check a log entry against all security rules.
        
        Args:
            entry: Log entry to check
            
        Returns:
            List of triggered alerts
        """
        alerts = []
        
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
        """
        Check for brute force login attempts.
        
        Detects excessive 401 responses from a single IP.
        """
        alerts = []
        
        if entry.status == 401:
            self.failed_logins[entry.ip].append(entry.time)
            
            # Clean old entries outside time window
            cutoff = entry.time - self.FAILED_LOGIN_WINDOW
            self.failed_logins[entry.ip] = [
                t for t in self.failed_logins[entry.ip]
                if t > cutoff
            ]
            
            # Check if threshold exceeded
            recent_count = len(self.failed_logins[entry.ip])
            if recent_count >= self.FAILED_LOGIN_THRESHOLD:
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
        """
        Check for access attempts to sensitive paths.
        """
        alerts = []
        path_lower = entry.path.lower()
        
        for sensitive_path in self.SENSITIVE_PATHS:
            if sensitive_path.lower() in path_lower:
                alerts.append(Alert(
                    rule="sensitive_path",
                    severity="medium",
                    message=f"Sensitive path access: {entry.path} from {entry.ip}",
                    ip=entry.ip,
                    path=entry.path,
                ))
                break
                
        return alerts
        
    def _check_scanning(self, entry: LogEntry) -> List[Alert]:
        """
        Check for scanning behavior.
        
        Detects IPs accessing many unique paths in short time.
        """
        alerts = []
        
        # Track path access per IP
        self.path_access[entry.ip][entry.path].append(entry.time)
        
        # Clean old entries
        cutoff = entry.time - self.SCANNING_WINDOW
        for ip in list(self.path_access.keys()):
            for path in list(self.path_access[ip].keys()):
                self.path_access[ip][path] = [
                    t for t in self.path_access[ip][path]
                    if t > cutoff
                ]
                if not self.path_access[ip][path]:
                    del self.path_access[ip][path]
            if not self.path_access[ip]:
                del self.path_access[ip]
                
        # Count unique paths for this IP
        unique_paths = len(self.path_access[entry.ip])
        
        if unique_paths >= self.SCANNING_THRESHOLD:
            alerts.append(Alert(
                rule="scanning",
                severity="medium",
                message=f"Possible scanning from {entry.ip} ({unique_paths} unique paths)",
                ip=entry.ip,
                count=unique_paths,
            ))
            
        return alerts
        
    def _check_high_rate(self, entry: LogEntry) -> List[Alert]:
        """
        Check for high request rate.
        
        Detects IPs with excessive requests in short time.
        """
        alerts = []
        
        self.request_times[entry.ip].append(entry.time)
        
        # Clean old entries
        cutoff = entry.time - self.HIGH_RATE_WINDOW
        self.request_times[entry.ip] = [
            t for t in self.request_times[entry.ip]
            if t > cutoff
        ]
        
        request_count = len(self.request_times[entry.ip])
        
        if request_count >= self.HIGH_RATE_THRESHOLD:
            alerts.append(Alert(
                rule="high_rate",
                severity="low",
                message=f"High request rate from {entry.ip} ({request_count} requests/min)",
                ip=entry.ip,
                count=request_count,
            ))
            
        return alerts
        
    def get_all_alerts(self) -> List[Alert]:
        """
        Get all triggered alerts.
        
        Returns:
            List of all alerts
        """
        return self.alerts
        
    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """
        Get alerts filtered by severity level.
        
        Args:
            severity: Severity level (high, medium, low)
            
        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts if a.severity == severity]
        
    def get_alerts_by_ip(self, ip: str) -> List[Alert]:
        """
        Get alerts for a specific IP.
        
        Args:
            ip: IP address to filter by
            
        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts if a.ip == ip]
        
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of security alerts.
        
        Returns:
            Dictionary with alert counts by severity
        """
        return {
            "total": len(self.alerts),
            "high": len(self.get_alerts_by_severity("high")),
            "medium": len(self.get_alerts_by_severity("medium")),
            "low": len(self.get_alerts_by_severity("low")),
        }
