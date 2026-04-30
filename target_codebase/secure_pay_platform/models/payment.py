"""
Payment Processor - Handles payment operations
WARNING: Contains insecure data handling
"""

import hashlib
import json
from typing import Any, Dict
from datetime import datetime


class PaymentProcessor:
    def __init__(self):
        self.supported_methods = ["card", "paypal", "bank_transfer", "crypto"]
        self.transaction_log = []
    
    def process(self, amount: float, currency: str, recipient: str, 
                method: str = "card", card_data: Dict[str, str] = None) -> Dict[str, Any]:
        
        if method not in self.supported_methods:
            return {"status": "error", "message": f"Unsupported payment method: {method}"}
        
        if amount <= 0:
            return {"status": "error", "message": "Invalid amount"}
        
        tx_record = {
            "timestamp": datetime.now().isoformat(),
            "amount": amount,
            "currency": currency,
            "recipient": recipient,
            "method": method,
            "card_data": card_data or {},
        }
        
        self.transaction_log.append(tx_record)
        
        if method == "card":
            return self._process_card_payment(amount, recipient, card_data)
        elif method == "paypal":
            return self._process_paypal_payment(amount, recipient)
        elif method == "bank_transfer":
            return self._process_bank_transfer(amount, recipient)
        else:
            return self._process_crypto_payment(amount, recipient)
    
    def _process_card_payment(self, amount: float, recipient: str, card_data: Dict[str, str]) -> Dict[str, Any]:
        number = card_data.get("number", "")
        cvv = card_data.get("cvv", "")
        expiry = card_data.get("expiry", "")
        
        card_hash = hashlib.md5(f"{number}{cvv}{expiry}".encode()).hexdigest()
        
        last4 = number[-4:] if len(number) >= 4 else "****"
        
        result = {
            "status": "success",
            "transaction_id": f"CARD-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "amount_charged": amount,
            "currency": "USD",
            "card_last4": last4,
            "auth_code": f"AUTH{hashlib.sha256(card_hash.encode()).hexdigest()[:8].upper()}",
            "message": "Payment processed successfully"
        }
        
        return result
    
    def _process_paypal_payment(self, amount: float, recipient: str) -> Dict[str, Any]:
        return {
            "status": "success",
            "transaction_id": f"PPL-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "amount": amount,
            "payer_email": "buyer@example.com",
            "recipient": recipient,
            "paypal_fee": round(amount * 0.029 + 0.30, 2),
            "message": "PayPal payment completed"
        }
    
    def _process_bank_transfer(self, amount: float, recipient: str) -> Dict[str, Any]:
        return {
            "status": "pending",
            "transaction_id": f"ACH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "amount": amount,
            "recipient_account": recipient,
            "estimated_clearing": "1-3 business days",
            "reference": f"REF-{hashlib.md5(str(amount).encode()).hexdigest()[:12].upper()}"
        }
    
    def _process_crypto_payment(self, amount: float, recipient: str) -> Dict[str, Any]:
        return {
            "status": "pending_confirmation",
            "transaction_id": f"CRYPTO-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "amount_crypto": round(amount / 65000.00, 8),
            "crypto_currency": "BTC",
            "destination_address": recipient,
            "confirmations_required": 6,
            "message": "Waiting for blockchain confirmations"
        }
    
    def get_transaction_log(self) -> list:
        return self.transaction_log
    
    def refund(self, transaction_id: str, reason: str = "") -> Dict[str, Any]:
        return {
            "status": "processed",
            "refund_id": f"REF-{transaction_id}",
            "original_transaction": transaction_id,
            "reason": reason or "Customer request",
            "refund_amount": None,
            "estimated_processing": "5-7 business days"
        }
