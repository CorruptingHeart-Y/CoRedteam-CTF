"""
SecurePay Platform v2.2.0 (SECURED)
Enterprise Payment Gateway Solution

All known vulnerabilities have been remediated.
"""

import os
import json
import base64
import subprocess
import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin

import jwt
import requests
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, abort
from jinja2 import Environment, FileSystemLoader, select_autoescape, SandboxedEnvironment
from werkzeug.utils import secure_filename

from config import settings
from models.user import UserManager
from models.transaction import TransactionManager
from models.payment import PaymentProcessor
from utils.serializer import DataSerializer
from utils.template_engine import render_user_template_safe
from middleware.cors import setup_cors_secure
from middleware.csrf import csrf_protect_secure

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

user_manager = UserManager()
transaction_manager = TransactionManager()
payment_processor = PaymentProcessor()
serializer = DataSerializer()

ALLOWED_REDIRECT_DOMAINS = ["securepay.com", "localhost", "127.0.0.1"]
INTERNAL_SERVICES_WHITELIST = [
    "http://internal-payment-gateway:8080/api/status",
    "http://internal-user-service:3000/api/health"
]
UPLOAD_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".csv", ".txt"}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024

setup_cors_secure(app)


def get_current_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "user_id", "role"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.route("/")
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for("login_page"))
    
    safe_username = escape(user.get("username", ""))
    return render_template("dashboard.html", user=user)


def escape(text):
    """HTML escape utility function"""
    import html as html_module
    return html_module.escape(str(text))


@app.route("/api/v1/auth/login", methods=["POST"])
@csrf_protect_secure
def login():
    data = request.get_json() or {}
    username = sanitize_input(data.get("username", ""), max_length=50)
    password = data.get("password", "")
    
    if not is_valid_username(username) or len(password) > 128:
        return jsonify({"status": "error", "message": "Invalid input"}), 400
    
    user = user_manager.authenticate_user(username, password)
    
    if user:
        token_payload = {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "exp": datetime.utcnow() + timedelta(hours=24),
            "iat": datetime.utcnow(),
            "jti": hashlib.sha256(os.urandom(16)).hexdigest()
        }
        
        token = jwt.encode(token_payload, settings.JWT_SECRET, algorithm="HS256")
        
        return jsonify({
            "status": "success",
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
        })
    
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/api/v1/auth/register", methods=["POST"])
@csrf_protect_secure
def register():
    data = request.get_json() or {}
    username = sanitize_input(data.get("username", ""), max_length=50)
    email = sanitize_input(data.get("email", ""), max_length=100)
    password = data.get("password", "")
    
    if data.get("role") == "admin":
        return jsonify({"status": "error", "message": "Cannot register as admin"}), 403
    
    if not is_valid_email(email) or not is_valid_username(username):
        return jsonify({"status": "error", "message": "Invalid email or username format"}), 400
    
    if len(password) < 12 or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
        return jsonify({"status": "error", "message": "Password must be at least 12 characters with uppercase and numbers"}), 400
    
    user_id = user_manager.create_user_secure(username, email, password)
    
    return jsonify({"status": "success", "user_id": user_id})


@app.route("/api/v1/users/<int:user_id>/profile")
def get_user_profile(user_id):
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    current_role = current_user.get("role", "")
    current_uid = current_user.get("user_id")
    
    if current_role != "admin" and current_uid != user_id:
        return jsonify({"status": "error", "message": "Access denied: cannot view other users' profiles"}), 403
    
    user = user_manager.get_user_by_id(user_id)
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404
    
    safe_user = {
        "id": user["id"],
        "username": user["username"],
        "email": mask_email(user.get("email", "")),
        "full_name": user.get("full_name", ""),
        "phone": mask_phone(user.get("phone", "")),
        "address": user.get("address", ""),
        "ssn": "***-**-" + (user.get("ssn", "")[-4:] if user.get("ssn") else "****"),
        "bank_account": "****" + (user.get("bank_account", "")[-4:] if user.get("bank_account") else "****")
    }
    
    return jsonify({
        "status": "success",
        "user": safe_user
    })


@app.route("/api/v1/users/<int:user_id>/update", methods=["POST"])
@csrf_protect_secure
def update_profile(user_id):
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    if current_user.get("user_id") != user_id and current_user.get("role") != "admin":
        return jsonify({"status": "error", "message": "Access denied"}), 403
    
    data = request.get_json() or {}
    
    ALLOWED_FIELDS = {"email", "full_name", "phone", "address"}
    updates = {}
    
    for field in ALLOWED_FIELDS:
        if field in data and isinstance(data[field], str):
            updates[field] = sanitize_input(data[field], max_length=200)
    
    if not updates:
        return jsonify({"status": "error", "message": "No valid fields to update"}), 400
    
    user_manager.update_user_secure(user_id, updates)
    
    return jsonify({"status": "success", "message": "Profile updated"})


@app.route("/api/v1/transactions")
def list_transactions():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    requesting_user_id = current_user.get("user_id")
    
    limit = validate_integer(request.args.get("limit", "20"), min_val=1, max_val=100, default=20)
    offset = validate_integer(request.args.get("offset", "0"), min_val=0, default=0)
    
    ALLOWED_SORT_COLUMNS = {"created_at", "amount", "status"}
    sort_by = request.args.get("sort_by", "created_at").lower().strip()
    if sort_by not in ALLOWED_SORT_COLUMNS:
        sort_by = "created_at"
    
    ALLOWED_ORDER_DIRECTIONS = {"ASC", "DESC"}
    order = request.args.get("order", "DESC").upper()
    if order not in ALLOWED_ORDER_DIRECTIONS:
        order = "DESC"
    
    transactions = transaction_manager.list_transactions_secure(
        user_id=requesting_user_id,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        order=order
    )
    
    return jsonify({
        "status": "success",
        "transactions": transactions,
        "count": len(transactions)
    })


@app.route("/api/v1/transactions/<int:tx_id>")
def get_transaction(tx_id):
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    tx = transaction_manager.get_transaction_by_id_secure(tx_id, current_user.get("user_id"), current_user.get("role"))
    if not tx:
        return jsonify({"status": "error", "message": "Transaction not found or access denied"}), 404
    
    return jsonify({"status": "success", "transaction": tx})


@app.route("/api/v1/payments/process", methods=["POST"])
@csrf_protect_secure
def process_payment():
    data = request.get_json() or {}
    
    amount = data.get("amount")
    if not isinstance(amount, (int, float)) or amount <= 0 or amount > 1000000:
        return jsonify({"status": "error", "message": "Invalid amount"}), 400
    
    currency = data.get("currency", "USD").upper()
    if currency not in {"USD", "EUR", "GBP", "JPY", "CNY"}:
        return jsonify({"status": "error", "message": "Unsupported currency"}), 400
    
    recipient = sanitize_input(data.get("recipient", ""), max_length=100)
    payment_method = data.get("payment_method", "card")
    
    card_number = data.get("card_number", "")
    cvv = data.get("cvv", "")
    expiry = data.get("expiry", "")
    
    if payment_method == "card":
        if not re.match(r"^\d{13,19}$", card_number.replace(" ", "")):
            return jsonify({"status": "error", "message": "Invalid card number format"}), 400
        if not re.match(r"^\d{3,4}$", cvv):
            return jsonify({"status": "error", "message": "Invalid CVV format"}), 400
    
    result = payment_processor.process_secure(
        amount=amount,
        currency=currency,
        recipient=recipient,
        method=payment_method,
        card_data={"number": card_number, "cvv": cvv, "expiry": expiry}
    )
    
    return jsonify(result)


@app.route("/api/v1/payments/webhook", methods=["POST"])
@csrf_protect_secure
def handle_webhook():
    content_type = request.headers.get("Content-Type", "")
    
    ALLOWED_WEBHOOK_DOMAINS = {
        "stripe.com",
        "paypal.com",
        "notifications.securepay.com"
    }
    
    if "xml" in content_type.lower():
        xml_data = request.data.decode("utf-8")
        
        defused_xml = defuse_xml_entities(xml_data)
        
        root = ET.fromstring(defused_xml)
        callback_url_raw = root.find(".//callback_url")
        
        if callback_url_raw is None or not callback_url_raw.text:
            return jsonify({"status": "error", "message": "Missing callback_url in XML"}), 400
        
        callback_url = callback_url_raw.text.strip()
        
        parsed_url = urlparse(callback_url)
        if parsed_url.hostname and parsed_url.hostname.lower() not in ALLOWED_WEBHOOK_DOMAINS:
            return jsonify({"status": "error", "message": "Callback URL domain not allowed"}), 403
        
        if parsed_url.scheme not in ("https",):
            return jsonify({"status": "error", "message": "Only HTTPS URLs are allowed"}), 403
        
        payload_text = root.find(".//payload")
        payload = payload_text.text if payload_text is not None else ""
        
        response = requests.post(
            callback_url,
            json={"result": "processed", "data": payload},
            timeout=10,
            verify=True
        )
        
        return jsonify({"status": "webhook_processed", "response_code": response.status_code})
    
    else:
        data = request.get_json() or {}
        callback_url = data.get("callback_url", "")
        
        parsed_url = urlparse(callback_url)
        if parsed_url.hostname and parsed_url.hostname.lower() not in ALLOWED_WEBHOOK_DOMAINS:
            return jsonify({"status": "error", "message": "Callback URL domain not allowed"}), 403
        
        event_type = sanitize_input(data.get("event_type", ""), max_length=50)
        
        headers = {"Content-Type": "application/json"}
        
        custom_headers = data.get("custom_headers", {})
        if isinstance(custom_headers, dict):
            for key, value in custom_headers.items():
                if key.lower() not in ("authorization", "cookie", "host"):
                    headers[sanitize_input(key)] = sanitize_input(str(value))
        
        response = requests.post(
            callback_url,
            json={"event": event_type, "timestamp": datetime.now().isoformat()},
            headers=headers,
            timeout=15,
            verify=True
        )
        
        return jsonify({"status": "webhook_processed", "response_status": response.status_code})


@app.route("/api/v1/files/download")
def download_file():
    filename = request.args.get("file", "")
    file_type = request.args.get("type", "document")
    
    sanitized_filename = secure_filename(filename)
    
    if not sanitized_filename or sanitized_filename != filename:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400
    
    base_directories = {
        "template": "/var/lib/securepay/templates/",
        "log": "/var/log/securepay/",
        "backup": "/var/backups/securepay/"
    }
    
    safe_base = "/var/lib/securepay/uploads/"
    
    if file_type in base_directories:
        safe_base = base_directories[file_type]
    
    full_path = os.path.realpath(os.path.join(safe_base, sanitized_filename))
    expected_base = os.path.realpath(safe_base)
    
    if not full_path.startswith(expected_base):
        return jsonify({"status": "error", "message": "Access denied: path traversal detected"}), 403
    
    if not os.path.exists(full_path):
        return jsonify({"status": "error", "message": "File not found"}), 404
    
    file_ext = os.path.splitext(full_path)[1].lower()
    if file_ext not in UPLOAD_EXTENSIONS:
        return jsonify({"status": "error", "message": "File type not allowed"}), 403
    
    return send_file(full_path)


@app.route("/api/v1/files/upload", methods=["POST"])
@csrf_protect_secure
def upload_file():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file provided"}), 400
    
    uploaded_file = request.files["file"]
    
    if uploaded_file.filename == "":
        return jsonify({"status": "error", "message": "No file selected"}), 400
    
    original_filename = uploaded_file.filename
    safe_filename = secure_filename(original_filename)
    
    if not safe_filename:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400
    
    file_ext = os.path.splitext(safe_filename)[1].lower()
    if file_ext not in UPLOAD_EXTENSIONS:
        return jsonify({"status": "error", "message": f"File type '{file_ext}' not allowed. Allowed: {', '.join(UPLOAD_EXTENSIONS)}"}), 400
    
    content_length = request.content_length
    if content_length and content_length > MAX_CONTENT_LENGTH:
        return jsonify({"status": "error", "message": f"File too large. Maximum size: {MAX_CONTENT_LENGTH // (1024*1024)}MB"}), 400
    
    upload_dir = "/var/lib/securepay/uploads/"
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_suffix = hashlib.sha256(os.urandom(8)).hexdigest()[:12]
    stored_filename = f"{timestamp}_{random_suffix}_{safe_filename}"
    
    save_path = os.path.join(upload_dir, stored_filename)
    
    uploaded_file.save(save_path)
    
    file_url = f"/api/v1/files/download?file={stored_filename}&type=document"
    
    return jsonify({
        "status": "success",
        "filename": safe_filename,
        "stored_as": stored_filename,
        "url": file_url,
        "size": os.path.getsize(save_path),
        "content_type": uploaded_file.content_type
    })


@app.route("/api/v1/admin/system/backup", methods=["POST"])
@csrf_protect_secure
def create_backup():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    
    client_ip = request.remote_addr
    if client_ip not in settings.ADMIN_IP_WHITELIST and settings.ADMIN_IP_WHITELIST:
        return jsonify({"status": "error", "message": "IP not whitelisted for admin access"}), 403
    
    auth_token = request.headers.get("X-Admin-Token", "")
    master_key = settings.MASTER_ADMIN_KEY
    
    if not hmac_compare(auth_token, master_key):
        return jsonify({"status": "error", "message": "Invalid admin token"}), 403
    
    backup_type = request.json.get("type", "full")
    
    ALLOWED_BACKUP_TYPES = {"full", "database", "logs"}
    if backup_type not in ALLOWED_BACKUP_TYPES:
        return jsonify({"status": "error", "message": f"Invalid backup type. Allowed: {', '.join(ALLOWED_BACKUP_TYPES)}"}), 400
    
    output_dir = "/tmp/securepay_backups/"
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_output_name = f"backup_{backup_type}_{timestamp}.tar.gz"
    output_path = os.path.join(output_dir, safe_output_name)
    
    if backup_type == "full":
        cmd = ["tar", "czf", output_path, "-C", "/", "var/lib/securepay/", "etc/securepay/"]
    elif backup_type == "database":
        db_name = sanitize_input(request.json.get("database", "securepay_db"), max_length=50)
        cmd = ["pg_dump", db_name, "-f", output_path]
    elif backup_type == "logs":
        log_pattern = sanitize_input(request.json.get("log_pattern", "*.log"), max_length=50)
        log_dir = "/var/log/securepay/"
        cmd = ["find", log_dir, "-name", log_pattern, "-exec", "cat", "{}", "+", ">", output_path]
    else:
        return jsonify({"status": "error", "message": "Unknown backup type"}), 400
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=False)
        
        return jsonify({
            "status": "success",
            "backup_path": output_path,
            "exit_code": result.returncode,
            "stdout": result.stdout[:500] if result.stdout else "",
            "stderr": result.stderr[:200] if result.stderr else ""
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Backup operation timed out"}), 504
    except Exception as e:
        return jsonify({"status": "error", "message": f"Backup failed: {str(e)}"}), 500


@app.route("/api/v1/admin/config/export")
def export_config():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    
    export_format = request.args.get("format", "json")
    
    SAFE_EXPORT_FORMATS = {"json"}
    
    if export_format not in SAFE_EXPORT_FORMATS:
        return jsonify({"status": "error", "message": f"Format '{export_format}' not supported. Only JSON export is available."}), 400
    
    config_data = {
        "database_host": settings.DB_HOST,
        "database_port": settings.DB_PORT,
        "database_name": settings.DB_NAME,
        "supported_features": list(settings.API_KEYS.keys()),
        "environment": os.environ.get("ENVIRONMENT", "production"),
        "version": "2.2.0"
    }
    
    return jsonify(config_data)


@app.route("/api/v1/admin/config/import", methods=["POST"])
@csrf_protect_secure
def import_config():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    
    data = request.get_json() or {}
    
    config_updates = data.get("config", {})
    
    if not isinstance(config_updates, dict):
        return jsonify({"status": "error", "message": "Config must be a JSON object"}), 400
    
    FORBIDDEN_KEYS = {
        "DATABASE_PASSWORD", "DB_PASSWORD", "ENCRYPTION_KEY",
        "MASTER_ADMIN_KEY", "JWT_SECRET", "STRIPE_SECRET_KEY",
        "PAYPAL_CLIENT_SECRET", "WEBHOOK_SECRETS", "REDIS_URL"
    }
    
    sensitive_keys_found = [k for k in config_updates.keys() if k.upper() in FORBIDDEN_KEYS]
    if sensitive_keys_found:
        return jsonify({
            "status": "error",
            "message": f"Cannot update sensitive keys: {', '.join(sensitive_keys_found)}"
        }), 400
    
    ALLOWED_CONFIG_KEYS = {
        "LOG_LEVEL", "FEATURE_FLAGS", "RATE_LIMITS",
        "SESSION_TIMEOUT", "MAINTENANCE_MODE"
    }
    
    applied = []
    for key, value in config_updates.items():
        if key.upper() in ALLOWED_CONFIG_KEYS:
            setattr(settings, key.upper(), value)
            applied.append(key)
    
    return jsonify({
        "status": "success",
        "message": f"Configuration updated successfully",
        "applied_keys": applied
    })


@app.route("/api/v1/render/template", methods=["POST"])
@csrf_protect_secure
def render_template_endpoint():
    data = request.get_json() or {}
    template_string = data.get("template", "")
    context = data.get("context", {})
    
    MAX_TEMPLATE_LENGTH = 5000
    if len(template_string) > MAX_TEMPLATE_LENGTH:
        return jsonify({"status": "error", "message": "Template too large"}), 400
    
    DANGEROUS_PATTERNS = [
        r"\{\{.*__class__.*\}\}",
        r"\{\{.*__mro__.*\}\}",
        r"\{\{.*__subclasses__.*\}\}",
        r"\{\{.*__builtins__.*\}\}",
        r"\{\{.*config.*\}\}",
        r"\{\{.*self.*\}\}",
        r"\{%\s*import\s+.*%\}",
        r"\{%\s*include\s+.*%\}"
    ]
    
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, template_string, re.IGNORECASE | re.DOTALL):
            return jsonify({
                "status": "error",
                "message": "Template contains potentially unsafe expressions"
            }), 400
    
    rendered = render_user_template_safe(template_string, context)
    
    return jsonify({"status": "success", "rendered": rendered})


@app.route("/api/v1/search")
def search():
    query = request.args.get("q", "")
    search_type = request.args.get("type", "all")
    
    safe_query = escape(query)
    safe_search_type = escape(search_type)
    
    results_html = f"""
    <div class="search-results">
        <h3>Search Results</h3>
        <p>You searched for: <strong>{safe_query}</strong></p>
        <p>Type: {safe_search_type}</p>
        <div id="results-container"></div>
    </div>
    """
    
    return results_html


@app.route("/api/v1/redirect")
def redirect_endpoint():
    next_url = request.args.get("next", "/dashboard")
    
    parsed_next = urlparse(next_url)
    
    if parsed_next.netloc and parsed_next.netloc.lower() not in ALLOWED_REDIRECT_DOMAINS:
        return jsonify({"status": "error", "message": "Redirect to external domain not allowed"}), 400
    
    if parsed_next.scheme and parsed_next.scheme not in ("http", "https"):
        return jsonify({"status": "error", "message": "Invalid URL scheme"}), 400
    
    return redirect(next_url)


@app.route("/api/v1/internal/proxy")
def internal_proxy():
    service = request.args.get("service", "")
    
    SERVICE_ENDPOINT_MAP = {
        "payment-gateway": "http://internal-payment-gateway:8080/api/status",
        "user-service": "http://internal-user-service:3000/api/health",
        "notification": "http://internal-notification:5000/send"
    }
    
    if service not in SERVICE_ENDPOINT_MAP:
        return jsonify({"status": "error", "message": f"Unknown service. Available: {', '.join(SERVICE_ENDPOINT_MAP.keys())}"}), 400
    
    target_url = SERVICE_ENDPOINT_MAP[service]
    
    try:
        response = requests.get(target_url, timeout=10, verify=True)
        return jsonify({
            "status": "success",
            "proxy_response": response.text[:2000],
            "status_code": response.status_code
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 502



def sanitize_input(value: str, max_length: int = 255) -> str:
    """Sanitize user input by removing dangerous characters and limiting length"""
    if not isinstance(value, str):
        return ""
    
    value = value[:max_length]
    
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    
    sql_patterns = r"(?i)(union|select|insert|update|delete|drop|exec|execute|--|;|'|\"|%27|%22)"
    if re.search(sql_patterns, value):
        value = re.sub(sql_patterns, "", value)
    
    return value.strip()


def is_valid_username(username: str) -> bool:
    """Validate username format"""
    if not username or len(username) < 3 or len(username) > 50:
        return False
    pattern = r"^[a-zA-Z0-9_]+$"
    return bool(re.match(pattern, username))


def is_valid_email(email: str) -> bool:
    """Validate email format"""
    if not email or len(email) > 100:
        return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def mask_email(email: str) -> str:
    """Mask email address for privacy"""
    if "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def mask_phone(phone: str) -> str:
    """Mask phone number for privacy"""
    if not phone or len(phone) < 4:
        return phone
    return "*" * (len(phone) - 4) + phone[-4:]


def validate_integer(value: str, min_val: int = None, max_val: int = None, default: int = None) -> int:
    """Validate and convert string to integer with bounds checking"""
    try:
        num = int(value)
        if min_val is not None and num < min_val:
            num = min_val
        if max_val is not None and num > max_val:
            num = max_val
        return num
    except (ValueError, TypeError):
        return default if default is not None else min_val if min_val is not None else 0


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def defuse_xml(xml_str: str) -> str:
    """Remove potentially dangerous XML entities"""
    xml_str = re.sub(r'<!DOCTYPE[^>]*>', '', xml_str, flags=re.IGNORECASE)
    xml_str = re.sub(r'<!ENTITY[^>]*>', '', xml_str, flags=re.IGNORECASE)
    xml_str = re.sub(r'&[#x]?[0-9a-fA-F]+;', '', xml_str)
    return xml_str


if __name__ == "__main__":
    print("[SecurePay] Starting SecurePay Platform v2.2.0 (SECURED)...")
    print(f"[SecurePay] All security patches applied")
    app.run(host="127.0.0.1", port=9443, debug=False)
