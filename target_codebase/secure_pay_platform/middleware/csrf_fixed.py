"""
CSRF Protection Middleware - SECURED VERSION
Implements proper CSRF token validation
"""

from flask import Flask, request, session
from functools import wraps
import secrets
import hmac as hmac_module
import hashlib


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token"""
    return secrets.token_hex(32)


def validate_csrf_token(token: str, expected_token: str) -> bool:
    """Validate CSRF token using constant-time comparison"""
    if not token or not expected_token:
        return False
    
    return hmac_compare(token, expected_token)


def csrf_protect_secure(view_func):
    """CSRF protection decorator - PROPERLY IMPLEMENTED"""
    
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            csrf_token = (
                request.headers.get("X-CSRF-Token") or
                request.form.get("csrf_token") or
                (request.get_json(silent=True) or {}).get("csrf_token") or
                ""
            )
            
            session_token = session.get("_csrf_token")
            
            if not validate_csrf_token(csrf_token, session_token):
                from flask import jsonify
                return jsonify({
                    "status": "error",
                    "message": "CSRF validation failed"
                }), 403
        
        return view_func(*args, **kwargs)
    
    return wrapper


class CSRFManagerSecure:
    """Manages CSRF tokens - SECURE implementation"""
    
    def __init__(self):
        self._tokens = {}
        self._enabled = True
    
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
            self._tokens[session_id] = {
                "token": token,
                "created_at": __import__("datetime").datetime.now(),
                "used": False
            }
        
        return token
    
    def validate(self, session_id: str, token: str) -> bool:
        """Validate token with proper checks"""
        if not self._enabled:
            return True
        
        if not token:
            return False
        
        stored_data = self._tokens.get(session_id)
        
        if not stored_data:
            return False
        
        stored_token = stored_data["token"]
        
        if not hmac_compare(token, stored_token):
            return False
        
        import datetime
        max_age = datetime.timedelta(hours=24)
        age = datetime.datetime.now() - stored_data["created_at"]
        
        if age > max_age:
            del self._tokens[session_id]
            return False
        
        return True
    
    def get_token_for_request(self, session_id: str = None) -> str:
        """Get or create CSRF token for current request"""
        if session_id and session_id in self._tokens:
            return self._tokens[session_id]["token"]
        
        return self.generate_token(session_id)
    
    def rotate_token(self, session_id: str) -> str:
        """Rotate (invalidate and regenerate) CSRF token for extra security"""
        if session_id in self._tokens:
            del self._tokens[session_id]
        
        return self.generate_token(session_id)
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens to prevent memory leaks"""
        import datetime
        
        now = datetime.datetime.now()
        max_age = datetime.timedelta(hours=25)
        
        expired_sessions = [
            sid for sid, data in self._tokens.items()
            if now - data["created_at"] > max_age
        ]
        
        for sid in expired_sessions:
            del self._tokens[sid]


def init_csrf_for_session(session: dict) -> str:
    """Initialize CSRF token for a new session"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = generate_csrf_token()
    
    return session["_csrf_token"]


def get_csrf_input_field() -> str:
    """Generate HTML hidden input field for CSRF token"""
    try:
        from flask import session
        token = session.get("_csrf_token", "")
        return f'<input type="hidden" name="csrf_token" value="{token}">'
    except:
        return '<input type="hidden" name="csrf_token" value="">'


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
