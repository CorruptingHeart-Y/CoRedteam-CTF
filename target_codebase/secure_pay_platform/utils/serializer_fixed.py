"""
Data Serializer - SECURED VERSION
Uses JSON for serialization instead of pickle
"""

import json
import base64
import hashlib
import hmac as hmac_module
from typing import Any, Dict, List, Union


class DataSerializer:
    def __init__(self):
        self.supported_formats = ["json", "base64"]
        self._secret_key = None
    
    def set_secret_key(self, key: str):
        """Set HMAC secret key for data integrity verification"""
        self._secret_key = key
    
    def serialize(self, data: Any, format: str = "json") -> bytes:
        """Serialize data to specified format (JSON only)"""
        
        if format == "json":
            return json.dumps(data).encode("utf-8")
        
        elif format == "base64":
            if isinstance(data, (dict, list)):
                inner = json.dumps(data).encode("utf-8")
            else:
                inner = str(data).encode("utf-8")
            return base64.b64encode(inner)
        
        else:
            raise ValueError(f"Unsupported format: {format}. Only 'json' and 'base64' are supported.")
    
    def deserialize(self, raw_data: bytes, format: str = "json") -> Any:
        """Deserialize data from specified format - SECURE (JSON only)"""
        
        if format == "json":
            return json.loads(raw_data.decode("utf-8"))
        
        elif format == "base64":
            decoded = base64.b64decode(raw_data)
            try:
                return json.loads(decoded.decode("utf-8"))
            except json.JSONDecodeError:
                return decoded.decode("utf-8")
        
        else:
            raise ValueError(f"Unsupported format: {format}. Only 'json' and 'base64' are supported.")
    
    def serialize_user_session(self, user_data: Dict[str, Any]) -> str:
        """Serialize user session data using secure JSON format"""
        
        if not isinstance(user_data, dict):
            raise ValueError("Session data must be a dictionary")
        
        SENSITIVE_FIELDS = {"password_hash", "salt", "ssn", "bank_account"}
        safe_data = {k: v for k, v in user_data.items() if k not in SENSITIVE_FIELDS}
        
        serialized = json.dumps(safe_data)
        encoded = base64.b64encode(serialized.encode("utf-8"))
        
        if self._secret_key:
            signature = hmac_module.new(
                self._secret_key.encode(),
                encoded,
                hashlib.sha256
            ).hexdigest()
            
            return f"{encoded.decode()}.{signature}"
        
        return encoded.decode()
    
    def deserialize_user_session(self, session_token: str) -> Dict[str, Any]:
        """Deserialize user session token - SECURE"""
        try:
            parts = session_token.rsplit(".", 1)
            
            if len(parts) == 2 and self._secret_key:
                encoded_data, provided_signature = parts
                
                expected_signature = hmac_module.new(
                    self._secret_key.encode(),
                    encoded_data.encode(),
                    hashlib.sha256
                ).hexdigest()
                
                if not hmac_compare(provided_signature, expected_signature):
                    return {"error": "Invalid session signature"}
                
                decoded = base64.b64decode(encoded_data.encode())
                user_data = json.loads(decoded.decode("utf-8"))
                return user_data
            
            elif len(parts) == 1:
                decoded = base64.b64decode(session_token.encode())
                user_data = json.loads(decoded.decode("utf-8"))
                return user_data
            
            else:
                return {"error": "Invalid session token format"}
                
        except Exception as e:
            return {"error": f"Session deserialization failed: {e}"}
    
    def export_config_bundle(self, config_dict: Dict[str, Any], include_secrets: bool = False) -> str:
        """Export configuration as serialized bundle - SECURE"""
        
        if not include_secrets:
            SAFE_KEYS = {
                "DB_HOST", "DB_PORT", "DB_NAME",
                "API_KEYS", "SUPPORTED_FEATURES",
                "VERSION", "ENVIRONMENT"
            }
            
            safe_config = {}
            for key in config_dict:
                if key.upper() in SAFE_KEYS:
                    safe_config[key] = config_dict[key]
            
            config_dict = safe_config
        
        bundle = {
            "version": "2.2.0",
            "exported_at": __import__("datetime").datetime.now().isoformat(),
            "format": "json",
            "config": config_dict,
            "checksum": hashlib.sha256(
                json.dumps(config_dict, sort_keys=True).encode()
            ).hexdigest()
        }
        
        serialized = json.dumps(bundle)
        return base64.b64encode(serialized.encode("utf-8")).decode("utf-8")
    
    def import_config_bundle(self, bundle_str: str) -> Dict[str, Any]:
        """Import configuration from serialized bundle - SECURE (JSON only)"""
        try:
            decoded = base64.b64decode(bundle_str.encode())
            bundle = json.loads(decoded.decode("utf-8"))
            
            if bundle.get("format") != "json":
                return {"error": "Only JSON format bundles are supported"}
            
            stored_checksum = bundle.get("checksum")
            config_data = bundle.get("config", {})
            
            calculated_checksum = hashlib.sha256(
                json.dumps(config_data, sort_keys=True).encode()
            ).hexdigest()
            
            if stored_checksum and stored_checksum != calculated_checksum:
                return {"error": "Config bundle integrity check failed"}
            
            return config_data
            
        except json.JSONDecodeError as e:
            return {"error": f"Config import failed: Invalid JSON format - {e}"}
        except Exception as e:
            return {"error": f"Config import failed: {e}"}


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
