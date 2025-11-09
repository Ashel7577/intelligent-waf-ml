#!/usr/bin/env python3
"""
Intelligent WAF Core Engine
Combines ML-based and rule-based threat detection
"""

import json
import re
import numpy as np
from datetime import datetime
import os
import sys

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from waf_config import config_manager, AttackSignatures
from ml_model import MLModelTrainer, extract_request_features

class IntelligentWAF:
    def __init__(self):
        self.config = config_manager.config
        self.ml_model = MLModelTrainer()
        self.attack_signatures = AttackSignatures()
        
        # Load ML model
        model_loaded = self.ml_model.load_model()
        if not model_loaded:
            print("⚠️ ML model not available, using rule-based detection only")
        
        print("🛡️ Intelligent WAF initialized")
        print(f"   ML Confidence Threshold: {self.config.ml_confidence_threshold}")
        print(f"   Rule Confidence Threshold: {self.config.rule_confidence_threshold}")
    
    def analyze_request(self, request_data):
        """
        Analyze HTTP request using both ML and rule-based methods
        """
        # Extract features for ML analysis
        try:
            features = extract_request_features(request_data)
        except Exception as e:
            print(f"[!] Error extracting features: {e}")
            features = {}
        
        # Perform ML analysis
        ml_result = self._ml_analysis(features)
        
        # Perform rule-based analysis
        rule_result = self._rule_based_analysis(request_data)
        
        # Combine results
        final_result = self._combine_analysis(ml_result, rule_result)
        
        return final_result
    
    def _ml_analysis(self, features):
        """
        Perform ML-based threat analysis
        """
        if not features:
            return {"prediction": "benign", "confidence": 0.0, "threat_type": "none"}
        
        try:
            # If ML model isn't available, return neutral result
            if self.ml_model.model is None:
                return {"prediction": "benign", "confidence": 0.0, "threat_type": "none"}
            
            # Make prediction
            result = self.ml_model.predict(features)
            
            return {
                "prediction": result["prediction"],
                "confidence": result["confidence"],
                "probabilities": result["probabilities"],
                "threat_type": "ml_detected" if result["prediction"] == "malicious" else "none"
            }
        except Exception as e:
            print(f"[!] ML analysis error: {e}")
            return {"prediction": "benign", "confidence": 0.0, "threat_type": "none"}
    
    def _rule_based_analysis(self, request_data):
        """
        Perform rule-based threat analysis using signature matching
        """
        threat_score = 0.0
        threat_details = []
        
        # Check URL for threats
        url = request_data.get("url", "")
        url_threats = self._check_patterns(url, [
            ("SQL Injection", self.attack_signatures.SQL_INJECTION_PATTERNS),
            ("XSS", self.attack_signatures.XSS_PATTERNS),
            ("Command Injection", self.attack_signatures.COMMAND_INJECTION_PATTERNS),
            ("LFI", self.attack_signatures.LFI_PATTERNS)
        ])
        
        threat_score += url_threats["score"]
        threat_details.extend(url_threats["details"])
        
        # Check headers
        headers_json = json.dumps(request_data.get("headers", {}))
        header_threats = self._check_patterns(headers_json, [
            ("SQL Injection", self.attack_signatures.SQL_INJECTION_PATTERNS),
            ("XSS", self.attack_signatures.XSS_PATTERNS),
            ("Command Injection", self.attack_signatures.COMMAND_INJECTION_PATTERNS)
        ])
        
        threat_score += header_threats["score"]
        threat_details.extend(header_threats["details"])
        
        # Check body/content
        body_content = ""
        if request_data.get("json"):
            body_content = json.dumps(request_data.get("json"))
        elif request_data.get("form"):
            body_content = json.dumps(request_data.get("form"))
        else:
            body_content = str(request_data.get("body", ""))
        
        body_threats = self._check_patterns(body_content, [
            ("SQL Injection", self.attack_signatures.SQL_INJECTION_PATTERNS),
            ("XSS", self.attack_signatures.XSS_PATTERNS),
            ("Command Injection", self.attack_signatures.COMMAND_INJECTION_PATTERNS)
        ])
        
        threat_score += body_threats["score"]
        threat_details.extend(body_threats["details"])
        
        # Determine overall threat level
        if threat_score >= self.config.rule_confidence_threshold:
            threat_type = "signature_match"
            if threat_details:
                threat_type = threat_details[0]["type"].lower().replace(" ", "_")
        else:
            threat_type = "none"
        
        return {
            "prediction": "malicious" if threat_score >= self.config.rule_confidence_threshold else "benign",
            "confidence": min(threat_score, 1.0),
            "threat_type": threat_type,
            "details": threat_details
        }
    
    def _check_patterns(self, text, pattern_groups):
        """
        Check text against multiple pattern groups
        """
        total_score = 0.0
        details = []
        
        if not text:
            return {"score": 0.0, "details": []}
        
        text_lower = text.lower()
        
        for threat_type, patterns in pattern_groups:
            matches = 0
            for pattern in patterns:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        matches += 1
                        details.append({
                            "type": threat_type,
                            "pattern": pattern,
                            "matched_text": text[:100] + "..." if len(text) > 100 else text
                        })
                except re.error:
                    # Skip invalid regex patterns
                    continue
            
            # Score based on number of matches
            if matches > 0:
                group_score = min(matches * 0.3, 0.8)  # Max 0.8 per threat type
                total_score += group_score
        
        return {"score": total_score, "details": details}
    
    def _combine_analysis(self, ml_result, rule_result):
        """
        Combine ML and rule-based analysis results
        """
        # Get confidence values
        ml_confidence = ml_result.get("confidence", 0.0)
        rule_confidence = rule_result.get("confidence", 0.0)
        
        # Determine if either method detected a threat
        ml_malicious = ml_result.get("prediction") == "malicious"
        rule_malicious = rule_result.get("prediction") == "malicious"
        
        # Combine confidence scores (weighted average)
        # Give more weight to rule-based if enabled and confident
        if self.config.enable_signature_matching and rule_confidence > 0.5:
            combined_confidence = (ml_confidence * 0.4) + (rule_confidence * 0.6)
        else:
            combined_confidence = ml_confidence
        
        # Determine final decision
        is_malicious = combined_confidence >= self.config.ml_confidence_threshold
        
        # Choose threat type
        threat_type = "none"
        if is_malicious:
            if rule_malicious and rule_result.get("threat_type") != "none":
                threat_type = rule_result.get("threat_type")
            elif ml_malicious:
                threat_type = "ml_detected"
            else:
                threat_type = "suspicious"
        
        return {
            "is_malicious": is_malicious,
            "confidence": combined_confidence,
            "threat_type": threat_type,
            "details": {
                "ml_analysis": ml_result,
                "rule_analysis": rule_result,
                "combined_confidence": combined_confidence
            }
        }
    
    def update_configuration(self, new_config):
        """
        Update WAF configuration
        """
        for key, value in new_config.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        print("✅ WAF configuration updated")

# Factory function
def create_intelligent_waf():
    """Factory function to create WAF instance"""
    return IntelligentWAF()

if __name__ == "__main__":
    # Test the WAF with sample requests
    waf = create_intelligent_waf()
    
    # Test benign request
    benign_request = {
        "method": "GET",
        "url": "/home",
        "headers": {"User-Agent": "Mozilla/5.0"},
        "remote_addr": "127.0.0.1"
    }
    
    result = waf.analyze_request(benign_request)
    print("Benign Request Result:", result)
    
    # Test malicious request
    malicious_request = {
        "method": "GET",
        "url": "/login?username=admin' OR '1'='1",
        "headers": {"User-Agent": "sqlmap/1.0"},
        "remote_addr": "127.0.0.1"
    }
    
    result = waf.analyze_request(malicious_request)
    print("Malicious Request Result:", result)
    
    print("✅ WAF core engine test completed")
