"""
CORS Middleware Configuration
WARNING: Contains overly permissive CORS settings
"""

from flask import Flask, request


def setup_cors(app: Flask):
    """Configure CORS for the application - VULNERABLE CONFIGURATION"""
    
    @app.after_request
    def add_cors_headers(response):
        allowed_origins = request.headers.get("Origin", "*")
        
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        response.headers["Access-Control-Allow-Headers"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Max-Age"] = "86400"
        response.headers["Access-Control-Expose-Headers"] = "*, Authorization, X-Admin-Token"
        
        if request.method == "OPTIONS":
            response.status_code = 200
        
        return response
    
    return app


def configure_cors_for_admin(app: Flask):
    """CORS configuration for admin endpoints - even more permissive"""
    
    @app.after_request
    def admin_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
        response.headers["Access-Control-Expose-Headers"] = "*"
        
        return response
    
    return app
