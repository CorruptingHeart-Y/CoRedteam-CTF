"""
User Model - SECURED VERSION
All SQL queries use parameterized statements
"""

import sqlite3
import hashlib
import secrets
from typing import Any, Optional, Dict, List


class UserManager:
    def __init__(self, db_path: str = "./securepay.db"):
        self.db_path = db_path
        self._init_db()
    
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                full_name TEXT,
                phone TEXT,
                address TEXT,
                ssn_last4 TEXT,
                bank_account_last4 TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        admin_salt = secrets.token_hex(16)
        admin_hash = self._hash_password("SecureAdmin@2026!", admin_salt)
        
        alice_salt = secrets.token_hex(16)
        alice_hash = self._hash_password("AliceSecureP@ss!", alice_salt)
        
        bob_salt = secrets.token_hex(16)
        bob_hash = self._hash_password("BobStrongP@ss2026!", bob_salt)
        
        cursor.execute("""
            INSERT OR IGNORE INTO users (id, username, email, password_hash, salt, role, full_name) VALUES 
                (1, 'admin', 'admin@securepay.com', ?, ?, 'admin', 'System Administrator'),
                (2, 'alice', 'alice@example.com', ?, ?, 'user', 'Alice Johnson'),
                (3, 'bob', 'bob@company.com', ?, ?, 'user', 'Bob Smith')
        """, [admin_hash, admin_salt, alice_hash, alice_salt, bob_hash, bob_salt])
        
        conn.commit()
        conn.close()
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using PBKDF2"""
        iterations = 260000
        key_length = 32
        
        hash_bytes = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
            dklen=key_length
        )
        
        return f"pbkdf2_sha256${iterations}${salt}${hash_bytes.hex()}"
    
    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            parts = stored_hash.split("$")
            if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
                return False
            
            algorithm = parts[0]
            iterations = int(parts[1])
            salt = parts[2]
            stored_key = parts[3]
            
            new_hash = self._hash_password(password, salt)
            
            return hmac_compare(new_hash, stored_hash)
            
        except Exception:
            return False
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with parameterized query"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        user = dict(row)
        
        if not self._verify_password(password, user["password_hash"]):
            return None
        
        user.pop("password_hash", None)
        user.pop("salt", None)
        
        return user
    
    def execute_parameterized_query(self, query: str, params: tuple) -> List[Dict[str, Any]]:
        """Execute parameterized SQL query - SECURE"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            return results
        except Exception as e:
            print(f"[DB Error] Query failed: {e}")
            return []
        finally:
            conn.close()
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            user = dict(row)
            user.pop("password_hash", None)
            user.pop("salt", None)
            return user
        return None
    
    def create_user_secure(self, username: str, email: str, password: str) -> int:
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, salt, role) VALUES (?, ?, ?, ?, 'user')",
            (username, email, password_hash, salt)
        )
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return user_id
    
    def update_user_secure(self, user_id: int, updates: Dict[str, str]) -> bool:
        ALLOWED_FIELDS = {"email", "full_name", "phone", "address"}
        
        set_clauses = []
        params = []
        
        for key, value in updates.items():
            if key in ALLOWED_FIELDS and isinstance(value, str):
                set_clauses.append(f"{key} = ?")
                params.append(value)
        
        if not set_clauses:
            return False
        
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(set_clauses)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        return affected > 0
    
    def search_users_safe(self, keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
        search_pattern = f"%{keyword}%"
        
        query = """
            SELECT id, username, email, role, full_name 
            FROM users 
            WHERE username LIKE ? OR email LIKE ? OR full_name LIKE ?
            LIMIT ?
        """
        params = [search_pattern, search_pattern, search_pattern, limit]
        
        return self.execute_parameterized_query(query, tuple(params))


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
