#!/usr/bin/env python3
"""Test dashboard imports and basic functionality"""

import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

print("🔍 Testing Dashboard Components...")

# Test import
try:
    from dashboard import create_dashboard_app
    print("✅ Dashboard import successful")
    
    # Test creating app
    app = create_dashboard_app()
    print("✅ Dashboard app creation successful")
    
    print("\n📋 Available functions:")
    print("  - create_dashboard_app()")
    print("  - start_dashboard(port=8080, ...)")  # Updated port info
    
    print("\n🚀 To start the dashboard:")
    print("   python3 src/dashboard.py")
    print("\n🌐 Access dashboard at: http://localhost:8080")
    
except Exception as e:
    print(f"❌ Dashboard test failed: {e}")
    import traceback
    traceback.print_exc()

print("\n✅ Dashboard test completed")
