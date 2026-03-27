"""Configuration loader for YAML-based rule customization."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class RuleConfig:
    """Configuration for a single security rule.
    
    Attributes:
        enabled: Whether the rule is enabled
        threshold: Threshold value to trigger alert
        time_window: Time window in seconds
    """
    enabled: bool = True
    threshold: int = 10
    time_window: int = 60


@dataclass
class Config:
    """Application configuration container.
    
    Attributes:
        brute_force: Brute force detection configuration
        sensitive_paths: List of sensitive paths to monitor
        scanning: Scanning detection configuration
        high_rate: High rate detection configuration
    """
    brute_force: RuleConfig = field(default_factory=RuleConfig)
    sensitive_paths: List[str] = field(default_factory=list)
    scanning: RuleConfig = field(
        default_factory=lambda: RuleConfig(threshold=20, time_window=300)
    )
    high_rate: RuleConfig = field(
        default_factory=lambda: RuleConfig(threshold=100)
    )

    def __post_init__(self) -> None:
        """Initialize default values."""
        if not self.sensitive_paths:
            self.sensitive_paths = self._get_default_sensitive_paths().copy()
    
    @staticmethod
    def _get_default_sensitive_paths() -> List[str]:
        """Get default list of sensitive paths.
        
        Returns:
            List of default sensitive path strings
        """
        return [
            "/admin",
            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/pma",
            "/.env",
            "/.git",
            "/.htaccess",
            "/config",
            "/backup",
            "/wp-config.php",
            "/xmlrpc.php",
        ]


class ConfigLoader:
    """Load and manage configuration from YAML file."""

    DEFAULT_CONFIG_PATH = "config.yaml"

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize config loader.

        Args:
            config_path: Path to YAML config file
        """
        self.config_path = (
            Path(config_path) if config_path else Path(self.DEFAULT_CONFIG_PATH)
        )
        self.config = Config()

    def load(self) -> Config:
        """
        Load configuration from YAML file.

        Creates default config file if not exists.

        Returns:
            Config object with loaded values
        """
        if not self.config_path.exists():
            # Create default config file
            self._create_default_config()
            return self.config

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data:
                self._parse_config(data)

        except Exception as e:
            # On error, use defaults
            print(f"Warning: Could not load config: {e}")
            print("Using default configuration.")

        return self.config

    def _create_default_config(self) -> None:
        """Create default configuration file."""
        default_config = {
            "# Strigoth Log Investigator - Configuration": None,
            "# Edit this file to customize security rules": None,
            "": None,  # Empty line
            "rules": {
                "brute_force": {
                    "enabled": True,
                    "threshold": 10,
                    "time_window": 60,
                    "description": "Detect brute force login attempts (401 responses)",
                },
                "sensitive_path": {
                    "enabled": True,
                    "paths": Config._get_default_sensitive_paths().copy(),
                    "description": "Detect access to sensitive paths",
                },
                "scanning": {
                    "enabled": True,
                    "threshold": 20,
                    "time_window": 300,
                    "description": "Detect scanning behavior (many unique paths)",
                },
                "high_rate": {
                    "enabled": True,
                    "threshold": 100,
                    "time_window": 60,
                    "description": "Detect high request rate",
                },
            },
        }

        # Write config file
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(
                default_config,
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

        print(f"Created default config file: {self.config_path}")

    def _parse_config(self, data: Dict[str, Any]) -> None:
        """
        Parse configuration data.

        Args:
            data: Configuration dictionary from YAML
        """
        rules = data.get("rules", {})

        # Parse brute force rule
        if "brute_force" in rules:
            bf = rules["brute_force"]
            self.config.brute_force = RuleConfig(
                enabled=bf.get("enabled", True),
                threshold=bf.get("threshold", 10),
                time_window=bf.get("time_window", 60),
            )

        # Parse sensitive paths
        if "sensitive_path" in rules:
            sp = rules["sensitive_path"]
            if sp.get("enabled", True):
                paths = sp.get("paths", Config._get_default_sensitive_paths().copy())
                self.config.sensitive_paths = (
                    paths if paths else Config._get_default_sensitive_paths().copy()
                )
            else:
                self.config.sensitive_paths = []

        # Parse scanning rule
        if "scanning" in rules:
            sc = rules["scanning"]
            self.config.scanning = RuleConfig(
                enabled=sc.get("enabled", True),
                threshold=sc.get("threshold", 20),
                time_window=sc.get("time_window", 300),
            )

        # Parse high rate rule
        if "high_rate" in rules:
            hr = rules["high_rate"]
            self.config.high_rate = RuleConfig(
                enabled=hr.get("enabled", True),
                threshold=hr.get("threshold", 100),
                time_window=hr.get("time_window", 60),
            )

    def get_config(self) -> Config:
        """
        Get current configuration.

        Returns:
            Config object
        """
        return self.config

    def reload(self) -> Config:
        """
        Reload configuration from file.

        Returns:
            Reloaded Config object
        """
        return self.load()


# Global config instance
_config: Optional[ConfigLoader] = None


def get_config() -> Config:
    """
    Get global configuration.

    Returns:
        Config object
    """
    global _config
    if _config is None:
        _config = ConfigLoader()
        _config.load()
    return _config.get_config()


def reload_config() -> Config:
    """
    Reload global configuration.

    Returns:
        Reloaded Config object
    """
    global _config
    if _config is None:
        _config = ConfigLoader()
    return _config.reload()
