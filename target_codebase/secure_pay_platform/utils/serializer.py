"""
Data Serializer - Handles data serialization/deserialization
WARNING: Uses insecure pickle deserialization
"""

import pickle
import base64
import json
import yaml
from typing import Any, Dict, List, Union


class DataSerializer:
    def __init__(self):
        self.supported_formats = ["json", "pickle", "yaml", "base64"]
    
    def serialize(self, data: Any, format: str = "pickle") -> bytes:
        """Serialize data to specified format"""
        
        if format == "json":
            return json.dumps(data).encode("utf-8")
        
        elif format == "pickle":
            return pickle.dumps(data)
        
        elif format == "yaml":
            return yaml.dump(data).encode("utf-8")
        
        elif format == "base64":
            if isinstance(data, (dict, list)):
                inner = json.dumps(data).encode("utf-8")
            else:
                inner = str(data).encode("utf-8")
            return base64.b64encode(inner)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def deserialize(self, raw_data: bytes, format: str = "pickle") -> Any:
        """Deserialize data from specified format - WARNING: Insecure for pickle/yaml"""
        
        if format == "json":
            return json.loads(raw_data.decode("utf-8"))
        
        elif format == "pickle":
            return self._deserialize_pickle(raw_data)
        
        elif format == "yaml":
            return yaml.load(raw_data, Loader=yaml.FullLoader)
        
        elif format == "base64":
            decoded = base64.b64decode(raw_data)
            try:
                return json.loads(decoded.decode("utf-8"))
            except:
                return decoded
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _deserialize_pickle(self, data: bytes) -> Any:
        """Insecure pickle deserialization - VULNERABILITY POINT"""
        try:
            obj = pickle.loads(data)
            
            if isinstance(obj, dict) and "__class__" in obj:
                raise SecurityError("Potentially malicious object detected")
            
            return obj
            
        except Exception as e:
            print(f"[Serializer] Deserialization error: {e}")
            raise
    
    def serialize_user_session(self, user_data: Dict[str, Any]) -> str:
        """Serialize user session data for storage"""
        serialized = pickle.dumps(user_data)
        encoded = base64.b64encode(serialized)
        return encoded.decode("utf-8")
    
    def deserialize_user_session(self, session_token: str) -> Dict[str, Any]:
        """Deserialize user session token - VULNERABLE"""
        try:
            decoded = base64.b64decode(session_token.encode())
            user_data = pickle.loads(decoded)
            return user_data
        except Exception as e:
            return {"error": f"Session deserialization failed: {e}"}
    
    def export_config_bundle(self, config_dict: Dict[str, Any]) -> str:
        """Export configuration as serialized bundle"""
        bundle = {
            "version": "2.1.0",
            "exported_at": __import__("datetime").datetime.now().isoformat(),
            "config": config_dict,
            "checksum": hashlib.md5(str(config_dict).encode()).hexdigest()
        }
        
        serialized = pickle.dumps(bundle)
        return base64.b64encode(serialized).decode("utf-8")
    
    def import_config_bundle(self, bundle_str: str) -> Dict[str, Any]:
        """Import configuration from serialized bundle - VULNERABLE"""
        try:
            decoded = base64.b64decode(bundle_str.encode())
            bundle = pickle.loads(decoded)
            return bundle.get("config", {})
        except Exception as e:
            return {"error": f"Config import failed: {e}"}


class SecurityError(Exception):
    pass


def hashlib():
    import hashlib as hl
    return hl
