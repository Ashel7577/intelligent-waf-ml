#!/usr/bin/env python3
"""
Main Application Entry Point for Intelligent WAF
Orchestrates all components of the WAF system
"""

import threading
import time
import sys
import os
from datetime import datetime

# Add src to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our modules with correct names
try:
    from ml_waf import IntelligentWAF
    from api_gateway import app as api_app, APISecurityGateway
    from data_collector import create_data_collector
    from dashboard import create_dashboard_app
    from waf_config import config_manager
    print("✅ All main modules imported successfully")
except ImportError as e:
    print(f"[!] Main import error: {e}")
    sys.exit(1)

def start_waf_service():
    """Start the WAF analysis service"""
    print("🚀 Starting Intelligent WAF Service...")
    waf = IntelligentWAF()
    return waf

def start_api_gateway(waf_instance=None):
    """Start the API gateway with WAF protection"""
    print("🛡️ Starting API Gateway...")
    
    # Initialize API gateway with WAF
    api_gateway = APISecurityGateway(waf_instance=waf_instance)
    
    # Update global reference in api_gateway module
    try:
        import api_gateway as api_module
        api_module.api_gateway = api_gateway
    except Exception as e:
        print(f"[!] Could not update api_gateway reference: {e}")
    
    # Start in separate thread
    def run_api():
        api_app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)
    
    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()
    print("✅ API Gateway running on port 8080")
    return api_thread

def start_dashboard_app(dashboard_app_instance, collector_instance=None):
    """Start the web dashboard"""
    print("📊 Starting Web Dashboard...")
    
    # Set the data collector for the dashboard
    try:
        import dashboard
        dashboard.data_collector = collector_instance
    except Exception as e:
        print(f"[!] Could not set dashboard data collector: {e}")
    
    def run_dashboard():
        dashboard_app_instance.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()
    print("✅ Dashboard running on port 5000")
    return dashboard_thread

def start_data_collection():
    """Start data collection service"""
    print("📈 Starting Data Collection Service...")
    collector = create_data_collector()
    collector.start_background_processing()
    return collector

def main():
    """Main application entry point"""
    print("=" * 60)
    print("🛡️  INTELLIGENT WEB APPLICATION FIREWALL (WAF)")
    print("=" * 60)
    print(f"📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Load configuration
        config = config_manager.config
        print("⚙️  Configuration loaded")
        
        # Start services in order
        print("\n🚀 Starting WAF Services...\n")
        
        # 1. Start WAF engine
        waf = start_waf_service()
        time.sleep(1)
        
        # 2. Start data collection
        collector = start_data_collection()
        time.sleep(1)
        
        # 3. Start API gateway with WAF
        api_thread = start_api_gateway(waf_instance=waf)
        time.sleep(1)
        
        # 4. Create and start dashboard
        dashboard_app_instance = create_dashboard_app(collector_instance=collector)
        dashboard_thread = start_dashboard_app(dashboard_app_instance, collector_instance=collector)
        time.sleep(1)
        
        print("\n" + "=" * 60)
        print("✅ ALL SERVICES STARTED SUCCESSFULLY")
        print("=" * 60)
        print("🔌 Endpoints:")
        print("   🔐 WAF Protected API: http://localhost:8080")
        print("   📊 Dashboard:         http://localhost:5000")
        print("   🛠️  Health Check:      http://localhost:8080/api/health")
        print("   🧪 Test Endpoint:     http://localhost:8080/api/test")
        print("=" * 60)
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n🛑 Shutting down services...")
            try:
                collector.stop_background_processing()
            except:
                pass
            print("👋 Goodbye!")
            sys.exit(0)
            
    except Exception as e:
        print(f"\n[!] Error starting services: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
