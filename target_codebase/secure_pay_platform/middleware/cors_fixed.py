"""
CORS Middleware Configuration - SECURED VERSION
Restricts CORS to allowed origins only
"""

from flask import Flask, request


ALLOWED_ORIGINS = [
    "https://securepay.com",
    "https://www.securepay.com",
    "https://app.securepay.com",
    "https://staging.securepay.com"
]

ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]

ALLOWED_HEADERS = [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-CSRF-Token"
]


def setup_cors_secure(app: Flask):
    """Configure secure CORS for the application"""
    
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif request.headers.get("Host") in ["localhost:9443", "127.0.0.1:9443"]:
            response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
        
        response.headers["Access-Control-Allow-Methods"] = ", ".join(ALLOWED_METHODS)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(ALLOWED_HEADERS)
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Max-Age"] = "3600"
        response.headers["Access-Control-Expose-Headers"] = "Authorization, X-Request-ID"
        
        if request.method == "OPTIONS":
            response.status_code = 200
        
        return response
    
    return app


def configure_cors_for_admin_secure(app: Flask):
    """Stricter CORS for admin endpoints"""
    
    ADMIN_ALLOWED_ORIGINS = [
        "https://admin.securepay.com",
        "https://securepay.com"
    ]
    
    @app.after_request
    def admin_cors_headers(response):
        origin = request.headers.get("Origin")
        
        if origin in ADMIN_ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, X-Admin-Token, X-CSRF-Token, Content-Type"
        response.headers["Access-Control-Expose-Headers"] = ""
        
        return response
    
    return app


def is_origin_allowed(origin: str) -> bool:
    """Check if an origin is in the allowlist"""
    if not origin:
        return False
    
    return origin in ALLOWED_ORIGINS or origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")
