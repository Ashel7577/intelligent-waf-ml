#!/usr/bin/env python3
"""
Configuration Management for Intelligent WAF
Handles settings, thresholds, and rule management
"""

import json
import os
from typing import Dict, Any, List
from dataclasses import dataclass
import re

@dataclass
class WAFConfig:
    """WAF Configuration Settings"""
    
    # ML Model Settings
    ml_confidence_threshold: float = 0.85
    ml_retrain_interval: int = 24  # hours
    ml_min_training_samples: int = 1000
    
    # Rule-based Settings
    rule_confidence_threshold: float = 0.7
    enable_signature_matching: bool = True
    enable_behavior_analysis: bool = True
    
    # Rate Limiting
    requests_per_minute: int = 1000
    max_concurrent_connections: int = 100
    ip_blacklist_duration: int = 3600  # seconds
    
    # Logging
    log_level: str = "INFO"
    enable_audit_log: bool = True
    log_retention_days: int = 30
    
    # Performance
    max_request_size: int = 1048576  # 1MB
    request_timeout: int = 30  # seconds
    enable_caching: bool = True
    
    # API Gateway
    api_key_required: bool = True
    enable_rate_limiting: bool = True
    cors_enabled: bool = True
    
    # Dashboard
    dashboard_port: int = 5000
    enable_live_monitoring: bool = True
    refresh_interval: int = 5  # seconds

class ConfigManager:
    """Configuration Manager for WAF Settings"""
    
    def __init__(self, config_file: str = "config/waf_config.json"):
        self.config_file = config_file
        self.config = WAFConfig()
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file or create default"""
        os.makedirs('config', exist_ok=True)
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self._update_config_from_dict(data)
                print(f"✅ Configuration loaded from {self.config_file}")
            except Exception as e:
                print(f"[!] Error loading config: {e}. Using defaults.")
                self._create_default_config()
        else:
            print("⚠️ Config file not found. Creating default configuration.")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration file"""
        default_config = {
            "ml_confidence_threshold": 0.85,
            "ml_retrain_interval": 24,
            "ml_min_training_samples": 1000,
            "rule_confidence_threshold": 0.7,
            "enable_signature_matching": True,
            "enable_behavior_analysis": True,
            "requests_per_minute": 1000,
            "max_concurrent_connections": 100,
            "ip_blacklist_duration": 3600,
            "log_level": "INFO",
            "enable_audit_log": True,
            "log_retention_days": 30,
            "max_request_size": 1048576,
            "request_timeout": 30,
            "enable_caching": True,
            "api_key_required": True,
            "enable_rate_limiting": True,
            "cors_enabled": True,
            "dashboard_port": 5000,
            "enable_live_monitoring": True,
            "refresh_interval": 5
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        print(f"✅ Default configuration created at {self.config_file}")
    
    def _update_config_from_dict(self, data: Dict[str, Any]):
        """Update configuration from dictionary"""
        for key, value in data.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
    
    def save_config(self):
        """Save current configuration to file"""
        config_dict = {
            key: getattr(self.config, key) 
            for key in vars(self.config).keys() 
            if not key.startswith('_')
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        print(f"✅ Configuration saved to {self.config_file}")
    
    def update_setting(self, key: str, value: Any):
        """Update a specific configuration setting"""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            self.save_config()
            return True
        else:
            print(f"[!] Invalid configuration key: {key}")
            return False
    
    def get_config_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return {
            key: getattr(self.config, key) 
            for key in vars(self.config).keys() 
            if not key.startswith('_')
        }
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return any issues"""
        issues = []
        
        # Validate ML thresholds
        if not 0 <= self.config.ml_confidence_threshold <= 1:
            issues.append("ML confidence threshold must be between 0 and 1")
        
        if not 0 <= self.config.rule_confidence_threshold <= 1:
            issues.append("Rule confidence threshold must be between 0 and 1")
        
        # Validate performance settings
        if self.config.max_request_size <= 0:
            issues.append("Max request size must be positive")
        
        if self.config.request_timeout <= 0:
            issues.append("Request timeout must be positive")
        
        # Validate rate limiting
        if self.config.requests_per_minute <= 0:
            issues.append("Requests per minute must be positive")
        
        return issues

# Attack Signature Rules
class AttackSignatures:
    """Attack signature patterns for rule-based detection"""
    
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL injection patterns
        r"union\s+select",  # Union select
        r"insert\s+into",  # Insert statements
        r"drop\s+table",  # Drop table
        r"delete\s+from",  # Delete statements
        r"update\s+\w+\s+set",  # Update statements
        r"exec(\s|\+)+(s|x)p\w+",  # Exec commands
        r"concat.*\(.*\)",  # Concat functions
        r"information_schema",  # Database schema access
        r"@@version",  # Version disclosure
        r"sleep\s*\(",  # Time-based attacks
        r"benchmark\s*\(",  # Benchmark attacks
    ]
    
    XSS_PATTERNS = [
        r"<script.*?>.*?<\/script>",  # Script tags
        r"javascript:",  # JavaScript protocol
        r"on\w+\s*=",  # Event handlers
        r"eval\s*\(",  # Eval functions
        r"expression\s*\(",  # CSS expressions
        r"data\s*:.*base64",  # Data URLs with base64
        r"<iframe.*?>",  # Iframe tags
        r"<object.*?>",  # Object tags
        r"<embed.*?>",  # Embed tags
        r"alert\s*\(",  # Alert functions
        r"document\.",  # Document object access
        r"window\.",  # Window object access
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(\||&|;|\n|\r|\$\(.*\)|`.*`)",  # Command separators
        r"(cat|ls|pwd|whoami|id|echo|wget|curl|nc|netcat)\s+",  # Common commands
        r"(\.{2,}\/)+",  # Path traversal
        r"(\w+\/){2,}",  # Deep path patterns
        r"\.{2,}",  # Double dots
        r"\$\{.*\}",  # Variable substitution
        r"\$\w+",  # Environment variables
        r"(\||&|;)\s*(\w+)",  # Command chaining
    ]
    
    LFI_PATTERNS = [
        r"(\.{2,}\/)+",  # Path traversal
        r"(\w+\/){2,}",  # Deep path patterns
        r"\.{2,}",  # Double dots
        r"%2e%2e%2f",  # URL encoded path traversal
        r"boot\.ini",  # Windows boot.ini
        r"etc\/passwd",  # Unix passwd file
    ]

# Create global config manager instance
config_manager = ConfigManager()

if __name__ == "__main__":
    print("🔧 WAF Configuration Manager")
    print("=============================")
    config_dict = config_manager.get_config_dict()
    for key, value in config_dict.items():
        print(f"{key}: {value}")
