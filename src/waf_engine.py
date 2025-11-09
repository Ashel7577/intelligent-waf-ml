"""
Intelligent Web Application Firewall (WAF)
Combines rule-based detection with machine learning for advanced threat protection
"""

import re
import json
import os
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

# Import data collector at module level
from data_collector import WAFDataCollector

class ThreatType(Enum):
    """Enumeration of threat types detected by the WAF"""
    NONE = "none"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"

@dataclass
class WAFResult:
    """Result of WAF analysis"""
    blocked: bool
    confidence: float
    threat_type: ThreatType
    details: str = ""

class IntelligentWAF:
    """Main WAF engine combining rule-based and ML detection"""
    
    def __init__(self, config_path: str = "config/waf_config.json"):
        """Initialize the WAF engine"""
        self.data_collector = WAFDataCollector()
        print("✅ WAF connected to data collector")
        
        # Load or create default configuration
        self.config = self._load_config(config_path)
        
        # Initialize threat detection patterns
        self._initialize_patterns()
        
        # Initialize ML model (placeholder)
        self.ml_model = None
        self._initialize_ml_model()
    
    def _load_config(self, config_path: str) -> Dict:
        """Load WAF configuration"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                # Create default configuration
                default_config = {
                    "security_level": "medium",
                    "log_blocked_requests": True,
                    "log_allowed_requests": False,
                    "dashboard_port": 8080
                }
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            print(f"⚠️ Config loading error: {e}")
            return {
                "security_level": "medium",
                "log_blocked_requests": True,
                "log_allowed_requests": False,
                "dashboard_port": 8080
            }
    
    def _initialize_patterns(self):
        """Initialize threat detection patterns"""
        # SQL Injection patterns
        self.sql_patterns = [
            r"(?i)union\s+select",
            r"(?i)\'\s*(or|and)\s*\'",
            r"(?i)\'\s*(or|and)\s*1",
            r"(?i)\'\s*;\s*(drop|delete|update|insert)",
            r"(?i)(exec|execute)\s*\(",
            r"(?i)xp_cmdshell",
            r"(?i)\'\s*--",
            r"(?i)\/\*\s*\*/",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(?i)<script.*?>",
            r"(?i)javascript:",
            r"(?i)on(load|error|click|mouseover|focus)\s*=",
            r"(?i)<iframe.*?>",
            r"(?i)eval\s*\(",
            r"(?i)data:text\/html",
        ]
        
        # Command injection patterns
        self.cmd_patterns = [
            r"(?i)\|\s*(cat|ls|pwd|whoami|id)",
            r"(?i)&\s*(cat|ls|pwd|whoami|id)",
            r"(?i)\$\((cat|ls|pwd|whoami|id)",
            r"(?i);.*(cat|ls|pwd|whoami|id)",
        ]
    
    def _initialize_ml_model(self):
        """Initialize ML model (placeholder)"""
        # In a real implementation, this would load a trained model
        self.ml_model = "placeholder"  # Placeholder for ML model
    
    def _detect_sql_injection(self, request: Dict) -> tuple[bool, float]:
        """Detect SQL injection attempts"""
        content = f"{request.get('url', '')} {request.get('body', '')} {request.get('query', '')}"
        
        for pattern in self.sql_patterns:
            if re.search(pattern, content):
                return True, 0.80
        
        return False, 0.05
    
    def _detect_xss(self, request: Dict) -> tuple[bool, float]:
        """Detect XSS attempts"""
        content = f"{request.get('url', '')} {request.get('body', '')} {request.get('query', '')}"
        
        for pattern in self.xss_patterns:
            if re.search(pattern, content):
                return True, 0.75
        
        return False, 0.05
    
    def _detect_command_injection(self, request: Dict) -> tuple[bool, float]:
        """Detect command injection attempts"""
        content = f"{request.get('url', '')} {request.get('body', '')} {request.get('query', '')}"
        
        for pattern in self.cmd_patterns:
            if re.search(pattern, content):
                return True, 0.85
        
        return False, 0.05
    
    def _analyze_with_rules(self, request: Dict) -> WAFResult:
        """Analyze request using rule-based detection"""
        # Check for SQL injection
        sql_detected, sql_confidence = self._detect_sql_injection(request)
        if sql_detected:
            return WAFResult(
                blocked=True,
                confidence=sql_confidence,
                threat_type=ThreatType.SQL_INJECTION,
                details="SQL Injection detected by pattern matching"
            )
        
        # Check for XSS
        xss_detected, xss_confidence = self._detect_xss(request)
        if xss_detected:
            return WAFResult(
                blocked=True,
                confidence=xss_confidence,
                threat_type=ThreatType.XSS,
                details="XSS detected by pattern matching"
            )
        
        # Check for command injection
        cmd_detected, cmd_confidence = self._detect_command_injection(request)
        if cmd_detected:
            return WAFResult(
                blocked=True,
                confidence=cmd_confidence,
                threat_type=ThreatType.COMMAND_INJECTION,
                details="Command injection detected by pattern matching"
            )
        
        # No threats detected
        return WAFResult(
            blocked=False,
            confidence=0.05,
            threat_type=ThreatType.NONE,
            details="No threats detected by rule-based engine"
        )
    
    def _analyze_with_ml(self, request: Dict) -> WAFResult:
        """Analyze request using ML model (placeholder)"""
        # In a real implementation, this would use a trained ML model
        # For now, we'll use a simple heuristic
        content_length = len(f"{request.get('url', '')} {request.get('body', '')}")
        
        # Simple heuristic: if content is very long, slightly increase confidence
        ml_confidence = min(0.1 + (content_length / 10000), 0.3)
        
        return WAFResult(
            blocked=False,  # ML model doesn't block in this placeholder
            confidence=ml_confidence,
            threat_type=ThreatType.NONE,
            details=f"ML analysis completed (content length: {content_length})"
        )
    
    def _log_request(self, request: Dict, result: WAFResult):
        """Log request to data collector"""
        try:
            self.data_collector.log_request(
                ip_address=request.get('ip_address', 'unknown'),
                method=request.get('method', 'GET'),
                url=request.get('url', '/'),
                is_malicious=result.blocked,
                confidence=result.confidence,
                threat_type=result.threat_type.value if result.threat_type != ThreatType.NONE else None,
                user_agent=request.get('user_agent'),
                response_code=403 if result.blocked else 200
            )
        except Exception as e:
            print(f"[!] Error logging request: {e}")
    
    def process_request(self, request: Dict) -> WAFResult:
        """Process an incoming request through the WAF"""
        print(f"🔍 Analyzing request: {request.get('method', 'GET')} {request.get('url', '/')} from {request.get('ip_address', 'unknown')}")
        
        # Analyze with rule-based engine
        rule_result = self._analyze_with_rules(request)
        
        # Analyze with ML model
        ml_result = self._analyze_with_ml(request)
        
        # Combine results (rule-based takes precedence for blocking)
        final_result = rule_result if rule_result.blocked else ml_result
        
        # Override with ML if it has higher confidence and is malicious
        if ml_result.confidence > rule_result.confidence and ml_result.confidence > 0.5:
            final_result = ml_result
        
        # Log the request
        self._log_request(request, final_result)
        
        # Print result
        status = "BLOCKED" if final_result.blocked else "ALLOWED"
        print(f"✅ {status}: {final_result.details} (confidence: {final_result.confidence:.2f})")
        
        return final_result

# Convenience function for testing
def test_waf():
    """Test the WAF with sample requests"""
    waf = IntelligentWAF()
    
    test_requests = [
        {
            'ip_address': '192.168.1.100',
            'method': 'GET',
            'url': '/api/users'
        },
        {
            'ip_address': '203.0.113.5',
            'method': 'GET',
            'url': '/search?q=admin\' OR \'1\'=\'1'
        },
        {
            'ip_address': '198.51.100.3',
            'method': 'POST',
            'url': '/comment',
            'body': '<script>alert("XSS")</script>'
        }
    ]
    
    for req in test_requests:
        print(f"\n--- Processing {req['method']} {req['url']} ---")
        result = waf.process_request(req)
        print(f"Result: {'BLOCKED' if result.blocked else 'ALLOWED'}")

if __name__ == "__main__":
    test_waf()
