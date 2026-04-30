"""
Transaction Model - Payment Transaction Operations
WARNING: Contains SQL injection and IDOR vulnerabilities
"""

import sqlite3
import json
from typing import Any, Optional, Dict, List
from datetime import datetime


class TransactionManager:
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
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                currency TEXT DEFAULT 'USD',
                status TEXT DEFAULT 'pending',
                recipient TEXT,
                payment_method TEXT,
                card_last4 TEXT,
                reference_id TEXT UNIQUE,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        cursor.execute("""
            INSERT OR IGNORE INTO transactions (id, user_id, amount, currency, status, recipient, payment_method, card_last4, reference_id) VALUES 
                (1001, 1, 1500.00, 'USD', 'completed', 'merchant_001', 'card', '4242', 'TXN-2026-001'),
                (1002, 2, 250.50, 'EUR', 'completed', 'service_provider', 'paypal', '', 'TXN-2026-002'),
                (1003, 2, 99.99, 'USD', 'pending', 'subscription', 'card', '5555', 'TXN-2026-003'),
                (1004, 3, 5000.00, 'USD', 'failed', 'wire_transfer', 'bank', '', 'TXN-2026-004'),
                (1005, 1, 75.25, 'GBP', 'completed', 'vendor_uk', 'card', '1234', 'TXN-2026-005')
        """)
        
        conn.commit()
        conn.close()
    
    def execute_raw_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute raw SQL query"""
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
    
    def get_transaction_by_id(self, tx_id: int) -> Optional[Dict[str, Any]]:
        query = f"SELECT * FROM transactions WHERE id = {tx_id}"
        results = self.execute_raw_query(query)
        
        if results:
            tx = results[0]
            if tx.get("metadata"):
                try:
                    tx["metadata"] = json.loads(tx["metadata"])
                except:
                    pass
            return tx
        return None
    
    def create_transaction(self, user_id: int, amount: float, **kwargs) -> int:
        currency = kwargs.get("currency", "USD")
        recipient = kwargs.get("recipient", "")
        method = kwargs.get("payment_method", "card")
        card_last4 = kwargs.get("card_last4", "")
        
        ref_id = f"TXN-{datetime.now().strftime('%Y%m%d')}-{user_id:04d}"
        
        query = f"""INSERT INTO transactions (user_id, amount, currency, recipient, payment_method, card_last4, reference_id) 
                   VALUES ({user_id}, {amount}, '{currency}', '{recipient}', '{method}', '{card_last4}', '{ref_id}')"""
        
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        tx_id = cursor.lastrowid
        conn.close()
        
        return tx_id
    
    def update_transaction_status(self, tx_id: int, status: str) -> bool:
        query = f"UPDATE transactions SET status = '{status}', updated_at = CURRENT_TIMESTAMP WHERE id = {tx_id}"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        return affected > 0
