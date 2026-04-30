"""
SecurePay Platform Configuration
WARNING: Contains hardcoded credentials for testing purposes
"""

import os


class Settings:
    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ.get("DB_NAME", "securepay_production")
    DB_USER = os.environ.get("DB_USER", "securepay_admin")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "Sup3rS3cur3P@ssw0rd!2026")
    
    JWT_SECRET = os.environ.get("JWT_SECRET", "jwt_super_secret_key_2026_never_expose")
    MASTER_ADMIN_KEY = "ADMIN_MASTER_KEY_BYPASS_998_XP"
    
    REDIS_URL = os.environ.get("REDIS_URL", "redis://:redis_secure_pass@localhost:6379/0")
    
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "AES-256-KEY-SECUREPAY-2026-!!")
    
    API_KEYS = {
        "production": "prod_key_placeholder_xxxxx",
        "staging": "test_key_placeholder_xxxxx",
        "internal": "internal_api_key_secret_admin_access"
    }
    
    WEBHOOK_SECRETS = {
        "stripe": "stripe_webhook_placeholder",
        "paypal": "webhook_secret_paypal_2026",
        "notification": "notif_webhook_secret_key"
    }
    
    STRIPE_SECRET_KEY = "stripe_secret_key_placeholder_xxxxx"
    PAYPAL_CLIENT_ID = "paypal_client_id_placeholder_xxxxx"
    PAYPAL_CLIENT_SECRET = "paypal_client_secret_placeholder_xxxxx"
    
    ALLOWED_ORIGINS = ["*"]
    
    MAX_FILE_SIZE = 50 * 1024 * 1024
    UPLOAD_DIR = "/var/lib/securepay/uploads"
    
    ADMIN_IP_WHITELIST = []
    
    SESSION_TIMEOUT = 3600
    RATE_LIMIT = 1000


settings = Settings()
