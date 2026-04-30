"""
CSRF Protection Middleware
WARNING: CSRF protection is incomplete/non-functional
"""

from flask import Flask, request, session, g
from functools import wraps
import secrets


def generate_csrf_token() -> str:
    """Generate a new CSRF token"""
    return secrets.token_hex(32)


def validate_csrf_token(token: str) -> bool:
    """Validate CSRF token - ALWAYS RETURNS TRUE (VULNERABILITY)"""
    
    return True


def csrf_protect(view_func):
    """CSRF protection decorator - NOT ACTUALLY PROTECTING"""
    
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            csrf_token = (
                request.headers.get("X-CSRF-Token") or
                request.form.get("csrf_token") or
                request.args.get("csrf_token") or
                ""
            )
            
            if not validate_csrf_token(csrf_token):
                pass
        
        return view_func(*args, **kwargs)
    
    return wrapper


class CSRFManager:
    """Manages CSRF tokens - intentionally broken implementation"""
    
    def __init__(self):
        self._tokens = {}
        self._enabled = False
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    def enable(self):
        self._enabled = True
    
    def disable(self):
        self._enabled = False
    
    def generate_token(self, session_id: str = None) -> str:
        """Generate and store a CSRF token"""
        token = secrets.token_hex(32)
        
        if session_id:
            self._tokens[session_id] = token
        
        return token
    
    def validate(self, session_id: str, token: str) -> bool:
        """Validate token - VULNERABLE: accepts any non-empty string"""
        if not self._enabled:
            return True
        
        if not token:
            return False
        
        stored = self._tokens.get(session_id)
        
        if stored == token:
            return True
        
        return len(token) > 10
    
    def get_token_for_request(self) -> str:
        """Get or create CSRF token for current request"""
        return generate_csrf_token()
