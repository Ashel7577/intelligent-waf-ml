"""
Data Collection Module for Intelligent WAF
Handles logging, statistics, and threat intelligence
"""

import sqlite3
import threading
import time
from datetime import datetime

class WAFDataCollector:
    """Singleton data collector for WAF statistics and logging"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_path="logs/waf_logs.db"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(WAFDataCollector, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path="logs/waf_logs.db"):
        if not self._initialized:
            self.db_path = db_path
            self.start_time = time.time()
            self._initialize_database()
            self._initialized = True
            print(f"✅ Database initialized successfully at {self.db_path}")
    
    def _initialize_database(self):
        """Initialize the SQLite database with required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS waf_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    is_malicious BOOLEAN NOT NULL,
                    threat_type TEXT,
                    confidence REAL NOT NULL,
                    user_agent TEXT,
                    response_code INTEGER
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            raise
    
    def log_request(self, ip_address, method, url, is_malicious, confidence, threat_type=None, user_agent=None, response_code=200):
        """Log a WAF request to the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO waf_logs 
                (timestamp, ip_address, method, url, is_malicious, threat_type, confidence, user_agent, response_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                ip_address,
                method,
                url,
                is_malicious,
                threat_type,
                confidence,
                user_agent,
                response_code
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Database logging error: {e}")
    
    def get_statistics(self):
        """Get WAF statistics from the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total requests
            cursor.execute('SELECT COUNT(*) FROM waf_logs')
            total_requests = cursor.fetchone()[0]
            
            # Get malicious requests
            cursor.execute('SELECT COUNT(*) FROM waf_logs WHERE is_malicious = 1')
            malicious_requests = cursor.fetchone()[0]
            
            # Get benign requests
            cursor.execute('SELECT COUNT(*) FROM waf_logs WHERE is_malicious = 0')
            benign_requests = cursor.fetchone()[0]
            
            # Calculate malicious percentage
            malicious_percentage = (malicious_requests / total_requests * 100) if total_requests > 0 else 0
            
            # Get average confidence
            if total_requests > 0:
                cursor.execute('SELECT AVG(confidence) FROM waf_logs')
                avg_confidence_result = cursor.fetchone()[0]
                average_confidence = float(avg_confidence_result) if avg_confidence_result is not None else 0
            else:
                average_confidence = 0
            
            # Calculate uptime
            uptime = time.time() - self.start_time
            
            conn.close()
            
            return {
                "total_requests": total_requests,
                "malicious_requests": malicious_requests,
                "benign_requests": benign_requests,
                "malicious_percentage": round(malicious_percentage, 2),
                "average_confidence": round(average_confidence, 4),
                "uptime": round(uptime, 1)
            }
        except Exception as e:
            print(f"❌ Statistics retrieval error: {e}")
            return {
                "total_requests": 0,
                "malicious_requests": 0,
                "benign_requests": 0,
                "malicious_percentage": 0,
                "average_confidence": 0,
                "uptime": 0
            }
    
    def get_recent_logs(self, limit=10):
        """Get recent WAF logs from the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # This enables column access by name
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, ip_address, method, url, is_malicious, threat_type, confidence
                FROM waf_logs
                ORDER BY id DESC
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            logs = []
            for row in rows:
                logs.append({
                    "timestamp": row["timestamp"],
                    "ip_address": row["ip_address"],
                    "method": row["method"],
                    "url": row["url"],
                    "is_malicious": bool(row["is_malicious"]),
                    "threat_type": row["threat_type"],
                    "confidence": float(row["confidence"])
                })
            
            return logs
        except Exception as e:
            print(f"❌ Recent logs retrieval error: {e}")
            return []
    
    def get_threat_distribution(self):
        """Get threat type distribution from the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT threat_type, COUNT(*) 
                FROM waf_logs 
                WHERE threat_type IS NOT NULL AND threat_type != 'none'
                GROUP BY threat_type
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            # Convert to dictionary with lowercase keys for consistency
            distribution = {}
            for threat_type, count in rows:
                if threat_type:  # Only add non-null threat types
                    key = threat_type.lower().replace(" ", "_")
                    distribution[key] = count
            
            return distribution
        except Exception as e:
            print(f"❌ Threat distribution retrieval error: {e}")
            return {}

# Convenience function to get the singleton instance
def get_data_collector():
    """Get the singleton data collector instance"""
    return WAFDataCollector()

