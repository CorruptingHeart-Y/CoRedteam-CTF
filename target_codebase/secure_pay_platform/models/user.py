"""
User Model - Database Operations
WARNING: Contains SQL injection vulnerabilities for testing
"""

import sqlite3
import hashlib
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
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                full_name TEXT,
                phone TEXT,
                address TEXT,
                ssn TEXT,
                bank_account TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            INSERT OR IGNORE INTO users (id, username, email, password, role, full_name)
            VALUES 
                (1, 'admin', 'admin@securepay.com', 'admin123', 'admin', 'System Administrator'),
                (2, 'alice', 'alice@example.com', 'password123', 'user', 'Alice Johnson'),
                (3, 'bob', 'bob@company.com', 'qwerty', 'user', 'Bob Smith')
        """)
        
        conn.commit()
        conn.close()
    
    def execute_raw_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute raw SQL query - WARNING: Vulnerable to injection"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            results = [dict(row) for row in cursor.fetchall()]
            return results
        except Exception as e:
            print(f"[DB Error] Query failed: {e}")
            return []
        finally:
            conn.close()
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        query = f"SELECT * FROM users WHERE id = {user_id}"
        results = self.execute_raw_query(query)
        return results[0] if results else None
    
    def create_user(self, username: str, email: str, password: str, role: str = "user") -> int:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        query = f"INSERT INTO users (username, email, password, role) VALUES ('{username}', '{email}', '{password_hash}', '{role}')"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return user_id
    
    def update_user(self, user_id: int, updates: Dict[str, str]) -> bool:
        set_clauses = []
        for key, value in updates.items():
            set_clauses.append(f"{key} = '{value}'")
        
        query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = {user_id}"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        return affected > 0
    
    def search_users(self, keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
        query = f"SELECT id, username, email, role, full_name FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%' OR full_name LIKE '%{keyword}%' LIMIT {limit}"
        return self.execute_raw_query(query)
