#!/usr/bin/env python3
"""
Integration test for the complete Intelligent WAF system
Tests all components working together
"""

import sys
import os
import time
import threading

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def test_full_integration():
    """Test all WAF components working together"""
    print("🚀 Testing Full WAF Integration...")
    
    try:
        # Import components
        from waf_engine import IntelligentWAF
        from data_collector import get_data_collector
        
        # Initialize WAF
        waf = IntelligentWAF()
        print("✅ WAF engine initialized")
        
        # Get data collector (same instance WAF uses)
        data_collector = get_data_collector()
        print("✅ Data collector connected")
        
        # Test requests
        test_requests = [
            {
                "ip_address": "192.168.1.100",
                "method": "GET",
                "url": "/api/users",
                "user_agent": "Mozilla/5.0"
            },
            {
                "ip_address": "203.0.113.5",
                "method": "GET",
                "url": "/search?q=admin'%20OR%20'1'%3D'1",
                "user_agent": "SuspiciousBot"
            },
            {
                "ip_address": "198.51.100.3",
                "method": "POST",
                "url": "/comment",
                "body": "<script>alert('XSS')</script>",
                "user_agent": "HackerBot"
            }
        ]
        
        print("\n🔍 Processing test requests...")
        for i, request in enumerate(test_requests, 1):
            print(f"\n--- Request {i} ---")
            result = waf.process_request(request)
            print(f"Result: {'BLOCKED' if result.blocked else 'ALLOWED'} "
                  f"(Confidence: {result.confidence:.2f})")
        
        # Check data collection
        print("\n📊 Checking data collection...")
        stats = data_collector.get_statistics()
        print(f"Statistics: {stats}")
        
        recent_logs = data_collector.get_recent_logs(5)
        print(f"\n📋 Recent logs ({len(recent_logs)} entries):")
        for log in recent_logs:
            status = "BLOCKED" if log['is_malicious'] else "ALLOWED"
            print(f"  {log['timestamp']} - {log['ip_address']} - {log['method']} {log['url']} - {status} ({log['confidence']:.2f})")
        
        threat_dist = data_collector.get_threat_distribution()
        print(f"\n⚠️  Threat distribution: {threat_dist}")
        
        # Verify results
        assert stats['total_requests'] >= 3, f"Expected at least 3 requests, got {stats['total_requests']}"
        assert stats['malicious_requests'] >= 1, f"Expected at least 1 malicious request, got {stats['malicious_requests']}"
        
        print("\n✅ Full integration test completed successfully!")
        print("💡 The dashboard should now show these results in real-time!")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_full_integration()
    sys.exit(0 if success else 1)
