#!/usr/bin/env python3
"""
Demo Script for Intelligent WAF
Shows various attack scenarios and WAF responses
"""

import sys
import time
sys.path.append('src')

from waf_engine import IntelligentWAF

def run_demo():
    """Run a comprehensive demo of the WAF"""
    print("🛡️ Intelligent WAF Demo")
    print("=" * 50)
    
    # Initialize WAF
    waf = IntelligentWAF()
    print("✅ WAF initialized\n")
    
    # Test cases
    test_cases = [
        # Legitimate requests
        {
            'name': 'Legitimate API Request',
            'request': {
                'ip_address': '192.168.1.100',
                'method': 'GET',
                'url': '/api/users'
            }
        },
        {
            'name': 'Normal User Profile Access',
            'request': {
                'ip_address': '192.168.1.101',
                'method': 'GET',
                'url': '/profile/settings'
            }
        },
        
        # SQL Injection attacks
        {
            'name': 'SQL Injection - Authentication Bypass',
            'request': {
                'ip_address': '203.0.113.5',
                'method': 'POST',
                'url': '/login',
                'body': "username=admin'; DROP TABLE users; --&password=pass"
            }
        },
        
        # XSS attacks
        {
            'name': 'XSS - Script Injection',
            'request': {
                'ip_address': '198.51.100.3',
                'method': 'POST',
                'url': '/comment',
                'body': '<script>alert("XSS")</script>'
            }
        },
        {
            'name': 'XSS - Image Tag Exploit',
            'request': {
                'ip_address': '203.0.113.6',
                'method': 'GET',
                'url': '/search?q=<img src=x onerror=alert(1)>'
            }
        },
        
        # Command Injection
        {
            'name': 'Command Injection - System Commands',
            'request': {
                'ip_address': '198.51.100.5',
                'method': 'POST',
                'url': '/upload',
                'body': "'; EXEC xp_cmdshell('dir'); --"
            }
        }
    ]
    
    # Process each test case
    for i, test_case in enumerate(test_cases, 1):
        print(f"🧪 Test {i}: {test_case['name']}")
        print(f"   Request: {test_case['request']['method']} {test_case['request']['url']}")
        if 'body' in test_case['request']:
            print(f"   Body: {test_case['request']['body'][:50]}...")
        
        result = waf.process_request(test_case['request'])
        status = "BLOCKED" if result.blocked else "ALLOWED"
        print(f"   Result: {status} (Confidence: {result.confidence:.2f})")
        if result.threat_type and result.threat_type.name != 'NONE':
            print(f"   Threat: {result.threat_type.name}")
        print()
        
        time.sleep(1)  # Pause between tests
    
    print("✅ Demo completed!")
    print("\n📊 Check the dashboard at http://localhost:8080 to see real-time results")

if __name__ == "__main__":
    run_demo()
