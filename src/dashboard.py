#!/usr/bin/env python3
"""
Real-time Dashboard for Intelligent WAF
Displays live security metrics and threat intelligence
"""

import os
import sys
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add src to path for imports
sys.path.append(os.path.dirname(__file__))

# Import data collector - fixed the class name
from data_collector import WAFDataCollector

# HTML template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intelligent WAF Dashboard</title>
    <style>
        :root {
            --primary: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #1f2937;
            --light: #f9fafb;
            --gray: #6b7280;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #f3f4f6;
            color: var(--dark);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary), #1d4ed8);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            color: var(--gray);
            font-size: 1rem;
        }
        
        .positive {
            color: var(--success);
        }
        
        .negative {
            color: var(--danger);
        }
        
        .warning {
            color: var(--warning);
        }
        
        .charts {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        @media (max-width: 768px) {
            .charts {
                grid-template-columns: 1fr;
            }
        }
        
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }
        
        .chart-title {
            font-size: 1.3rem;
            margin-bottom: 15px;
            color: var(--dark);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        
        th {
            background-color: #f9fafb;
            font-weight: 600;
            color: var(--gray);
        }
        
        tr:hover {
            background-color: #f9fafb;
        }
        
        .status-badge {
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        .allowed {
            background-color: #dcfce7;
            color: var(--success);
        }
        
        .blocked {
            background-color: #fee2e2;
            color: var(--danger);
        }
        
        .confidence-high {
            color: var(--danger);
            font-weight: bold;
        }
        
        .confidence-medium {
            color: var(--warning);
        }
        
        .confidence-low {
            color: var(--success);
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: var(--gray);
            font-size: 0.9rem;
        }
        
        .last-updated {
            text-align: right;
            font-size: 0.9rem;
            color: var(--gray);
            margin-top: 10px;
        }
        
        .system-status {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 10px;
            font-size: 0.9rem;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background-color: var(--success);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Intelligent WAF Dashboard</h1>
            <p class="subtitle">Real-time threat monitoring and analysis</p>
            <div class="system-status">
                <div class="status-indicator"></div>
                <span>System operational | Data collector connected</span>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value" id="total-requests">0</div>
                <div class="stat-label">All traffic monitored</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Blocked Threats</div>
                <div class="stat-value negative" id="blocked-threats">0</div>
                <div class="stat-label">Prevented attacks</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Detection Rate</div>
                <div class="stat-value warning" id="detection-rate">0%</div>
                <div class="stat-label">Threat identification</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Avg Confidence</div>
                <div class="stat-value positive" id="avg-confidence">0.0000</div>
                <div class="stat-label">Model accuracy</div>
            </div>
        </div>
        
        <div class="charts">
            <div class="chart-container">
                <h2 class="chart-title">📈 Recent Activity</h2>
                <table id="recent-activity">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP Address</th>
                            <th>Request</th>
                            <th>Status</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td colspan="5" style="text-align: center;">Loading data...</td>
                        </tr>
                    </tbody>
                </table>
                <div class="last-updated">Last updated: <span id="last-updated">Never</span></div>
            </div>
            
            <div class="chart-container">
                <h2 class="chart-title">⚠️ Threat Distribution</h2>
                <table id="threat-distribution">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td colspan="2" style="text-align: center;">Loading data...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <footer>
            <p>Intelligent WAF v1.0 | Real-time Security Monitoring Dashboard</p>
        </footer>
    </div>
    
    <script>
        // Function to fetch data from API
        async function fetchData() {
            try {
                const response = await fetch('/api/data?t=' + new Date().getTime()); // Prevent caching
                const data = await response.json();
                updateDashboard(data);
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }
        
        // Function to update dashboard with new data
        function updateDashboard(data) {
            // Update statistics
            document.getElementById('total-requests').textContent = data.statistics.total_requests;
            document.getElementById('blocked-threats').textContent = data.statistics.malicious_requests;
            document.getElementById('detection-rate').textContent = data.statistics.malicious_percentage + '%';
            document.getElementById('avg-confidence').textContent = data.statistics.average_confidence.toFixed(4);
            
            // Update recent activity table
            const activityTable = document.getElementById('recent-activity').getElementsByTagName('tbody')[0];
            activityTable.innerHTML = '';
            
            if (data.recent_logs.length === 0) {
                const row = activityTable.insertRow();
                const cell = row.insertCell(0);
                cell.colSpan = 5;
                cell.textContent = 'No recent activity';
                cell.style.textAlign = 'center';
            } else {
                data.recent_logs.forEach(log => {
                    const row = activityTable.insertRow();
                    
                    // Time
                    const timeCell = row.insertCell(0);
                    timeCell.textContent = log.timestamp.split(' ')[1]; // Just show time part
                    
                    // IP Address
                    const ipCell = row.insertCell(1);
                    ipCell.textContent = log.ip_address;
                    
                    // Request
                    const requestCell = row.insertCell(2);
                    requestCell.textContent = `${log.method} ${log.url}`;
                    
                    // Status
                    const statusCell = row.insertCell(3);
                    const statusBadge = document.createElement('span');
                    statusBadge.className = 'status-badge ' + (log.is_malicious ? 'blocked' : 'allowed');
                    statusBadge.textContent = log.is_malicious ? 'BLOCKED' : 'ALLOWED';
                    statusCell.appendChild(statusBadge);
                    
                    // Confidence
                    const confidenceCell = row.insertCell(4);
                    let confidenceClass = 'confidence-low';
                    if (log.confidence >= 0.7) {
                        confidenceClass = 'confidence-high';
                    } else if (log.confidence >= 0.4) {
                        confidenceClass = 'confidence-medium';
                    }
                    confidenceCell.innerHTML = `<span class="${confidenceClass}">${log.confidence.toFixed(2)}</span>`;
                });
            }
            
            // Update threat distribution table
            const threatTable = document.getElementById('threat-distribution').getElementsByTagName('tbody')[0];
            threatTable.innerHTML = '';
            
            if (Object.keys(data.threat_distribution).length === 0) {
                const row = threatTable.insertRow();
                const cell = row.insertCell(0);
                cell.colSpan = 2;
                cell.textContent = 'No threats detected';
                cell.style.textAlign = 'center';
            } else {
                Object.entries(data.threat_distribution).forEach(([type, count]) => {
                    const row = threatTable.insertRow();
                    
                    const typeCell = row.insertCell(0);
                    typeCell.textContent = type.replace('_', ' ').toUpperCase();
                    
                    const countCell = row.insertCell(1);
                    countCell.textContent = count;
                });
            }
            
            // Update last updated time
            document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
        }
        
        // Fetch data initially and then every 2 seconds
        fetchData();
        setInterval(fetchData, 2000);
    </script>
</body>
</html>
'''

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging to keep console clean
        return
    
    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/':
            # Serve the dashboard HTML
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode())
            
        elif parsed_path.path == '/api/data':
            # Serve JSON data - CRITICAL: Create a NEW data collector instance for each request
            # This ensures we read fresh data from the database each time
            try:
                # Create fresh instance for fresh data
                data_collector = WAFDataCollector("logs/waf_logs.db")
                
                statistics = data_collector.get_statistics()
                recent_logs = data_collector.get_recent_logs(20)  # Last 20 requests
                threat_distribution = data_collector.get_threat_distribution()
                
                # Prepare JSON response
                response_data = {
                    "statistics": statistics,
                    "recent_logs": recent_logs,
                    "threat_distribution": threat_distribution,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
                
            except Exception as e:
                self.send_error(500, f"Internal Server Error: {str(e)}")
        else:
            self.send_error(404, "Not Found")

def run_dashboard(port=8080):
    """Run the WAF dashboard server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, DashboardHandler)
    print(f"🚀 Starting WAF Dashboard on port {port}")
    print(f"🌐 Visit: http://localhost:{port}")
    print("💡 Tip: Process some requests through the WAF to see data populate!")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Stopping dashboard server...")
        httpd.shutdown()

if __name__ == "__main__":
    # Get port from config or default to 8080
    port = 8080
    try:
        import json
        with open("config/waf_config.json", "r") as f:
            config = json.load(f)
            port = config.get("dashboard_port", 8080)
    except:
        pass
    
    run_dashboard(port)
