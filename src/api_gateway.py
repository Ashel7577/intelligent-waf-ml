#!/usr/bin/env python3
"""
API Gateway with Integrated WAF Protection
Provides API security, rate limiting, and request filtering
"""

from flask import Flask, request, jsonify, make_response
import time
import json
import redis
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import hashlib
import hmac
import base64
import os
import re

app = Flask(__name__)

# Simple in-memory storage for rate limiting (use Redis in production)
rate_limits = defaultdict(list)  # IP -> list of timestamps
blocked_ips = {}  # IP -> expiry timestamp

# Mock API keys for testing
API_KEYS = {
    "test-api-key-123": "test-client",
    "prod-api-key-456": "production-client"
}

class APISecurityGateway:
    def __init__(self, waf_instance=None):
        self.waf = waf_instance
        self.redis_client = None
        try:
            self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            self.redis_client.ping()
            print("✅ Connected to Redis")
        except:
            print("⚠️ Redis not available, using in-memory storage")

    def apply_rate_limiting(self, ip_address):
        """Apply rate limiting to requests"""
        current_time = time.time()
        
        # Check if IP is blocked
        if ip_address in blocked_ips:
            if blocked_ips[ip_address] > current_time:
                return False, "IP temporarily blocked due to rate limiting"
            else:
                del blocked_ips[ip_address]
        
        # Clean old entries (older than 1 minute)
        if self.redis_client:
            # Use Redis for distributed rate limiting
            key = f"rate_limit:{ip_address}"
            pipeline = self.redis_client.pipeline()
            pipeline.zremrangebyscore(key, 0, current_time - 60)
            pipeline.zcard(key)
            pipeline.expire(key, 60)
            results = pipeline.execute()
            request_count = results[1]
            
            if request_count >= 100:  # 100 requests per minute
                blocked_ips[ip_address] = current_time + 3600  # Block for 1 hour
                return False, "Rate limit exceeded"
            
            # Add current request
            self.redis_client.zadd(key, {str(current_time): current_time})
            return True, "OK"
        else:
            # Fallback to in-memory rate limiting
            if ip_address in rate_limits:
                # Remove old entries
                rate_limits[ip_address] = [
                    timestamp for timestamp in rate_limits[ip_address]
                    if timestamp > current_time - 60
                ]
                
                # Check if limit exceeded
                if len(rate_limits[ip_address]) >= 100:  # 100 requests per minute
                    blocked_ips[ip_address] = current_time + 3600  # Block for 1 hour
                    return False, "Rate limit exceeded"
            
            # Add current request
            rate_limits[ip_address].append(current_time)
            return True, "OK"

    def validate_api_key(self, api_key):
        """Validate API key"""
        return api_key in API_KEYS

    def sanitize_input(self, data):
        """Sanitize input data"""
        if isinstance(data, str):
            # Remove dangerous characters
            data = re.sub(r'[<>]', '', data)
            return data
        elif isinstance(data, dict):
            return {k: self.sanitize_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_input(item) for item in data]
        return data

    def analyze_request(self, request_data):
        """Analyze request using WAF"""
        if self.waf:
            return self.waf.analyze_request(request_data)
        else:
            # Mock analysis for testing
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "threat_type": "none",
                "details": "WAF not initialized"
            }

# Global instance
api_gateway = None

@app.before_request
def before_request():
    """Process request before handling"""
    global api_gateway
    
    if not api_gateway:
        return
    
    client_ip = request.remote_addr
    
    # Apply rate limiting
    if api_gateway:
        allowed, message = api_gateway.apply_rate_limiting(client_ip)
        if not allowed:
            return jsonify({"error": "Rate limit exceeded", "message": message}), 429
    
    # Validate API key if required
    if api_gateway and api_gateway.waf and api_gateway.waf.config.api_key_required:
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key or not api_gateway.validate_api_key(api_key):
            return jsonify({"error": "Invalid or missing API key"}), 401

@app.route('/')
def home():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "service": "Intelligent WAF API Gateway",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Test endpoint protected by WAF"""
    request_data = {
        "method": request.method,
        "url": request.url,
        "headers": dict(request.headers),
        "args": dict(request.args),
        "form": dict(request.form),
        "json": request.get_json() if request.is_json else None,
        "remote_addr": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', '')
    }
    
    # Analyze with WAF
    if api_gateway:
        waf_result = api_gateway.analyze_request(request_data)
        
        if waf_result.get("is_malicious", False):
            return jsonify({
                "error": "Request blocked by WAF",
                "threat": waf_result.get("threat_type"),
                "confidence": waf_result.get("confidence")
            }), 403
    
    # Return sanitized response
    sanitized_data = request_data
    if api_gateway:
        sanitized_data = api_gateway.sanitize_input(request_data)
    
    return jsonify({
        "message": "Request processed successfully",
        "request": sanitized_data,
        "waf_analysis": waf_result if 'waf_result' in locals() else {"status": "WAF not active"}
    })

@app.route('/api/protected', methods=['GET', 'POST'])
def protected_endpoint():
    """Protected endpoint requiring API key"""
    return jsonify({
        "message": "Protected endpoint accessed successfully",
        "timestamp": datetime.now().isoformat()
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
