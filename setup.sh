#!/bin/bash

echo "🛡️ Setting up Intelligent WAF with ML..."

# Create directories
mkdir -p logs config

# Install Python dependencies
if command -v pip3 &> /dev/null; then
    echo "📦 Installing Python dependencies..."
    pip3 install -r requirements.txt
elif command -v pip &> /dev/null; then
    echo "📦 Installing Python dependencies..."
    pip install -r requirements.txt
else
    echo "⚠️ Please install pip to continue"
    exit 1
fi

# Initialize database by running a simple test
echo "🔧 Initializing database..."
python3 -c "
import sys
sys.path.append('src')
try:
    from data_collector import WAFDataCollector
    collector = WAFDataCollector()
    print('✅ Database initialized successfully')
except Exception as e:
    print(f'❌ Error initializing database: {e}')
"

echo "✅ Setup complete!"
echo ""
echo "🚀 To start the dashboard:"
echo "   python3 src/dashboard.py"
echo ""
echo "🔗 Access dashboard at: http://localhost:8080"
echo ""
echo "🧪 To test the WAF:"
echo "   python3 -c \""
echo "   import sys"
echo "   sys.path.append('src')"
echo "   from waf_engine import IntelligentWAF"
echo "   waf = IntelligentWAF()"
echo "   waf.process_request({'ip_address': '192.168.1.100', 'method': 'GET', 'url': '/test'})"
echo "   \""  
