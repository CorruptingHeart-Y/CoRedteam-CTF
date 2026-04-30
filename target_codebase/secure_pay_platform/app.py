"""
SecurePay Platform v2.1.0
Enterprise Payment Gateway Solution

WARNING: This is a deliberately vulnerable application for security testing.
DO NOT deploy in production environment.
"""

import os
import json
import pickle
import base64
import subprocess
import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from functools import wraps

import jwt
import requests
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for
from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import settings
from models.user import UserManager
from models.transaction import TransactionManager
from models.payment import PaymentProcessor
from utils.serializer import DataSerializer
from utils.template_engine import render_user_template
from middleware.cors import setup_cors
from middleware.csrf import csrf_protect

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY_2026_DO_NOT_SHARE"

user_manager = UserManager()
transaction_manager = TransactionManager()
payment_processor = PaymentProcessor()
serializer = DataSerializer()

setup_cors(app)


def get_current_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload
    except Exception:
        return None


@app.route("/")
def index():
    return render_template("dashboard.html", user=get_current_user())


@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = user_manager.execute_raw_query(query)
    
    if user:
        secret_key = settings.JWT_SECRET or "default_secret"
        algorithm = request.headers.get("X-JWT-Alg", "HS256")
        
        token_payload = {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        
        token = jwt.encode(token_payload, secret_key, algorithm=algorithm)
        
        return jsonify({
            "status": "success",
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
        })
    
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/api/v1/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")
    role = data.get("role", "user")
    
    if role == "admin":
        return jsonify({"status": "error", "message": "Cannot register as admin"}), 403
    
    user_id = user_manager.create_user(username, email, password, role)
    
    return jsonify({"status": "success", "user_id": user_id})


@app.route("/api/v1/users/<int:user_id>/profile")
def get_user_profile(user_id):
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    user = user_manager.get_user_by_id(user_id)
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404
    
    return jsonify({
        "status": "success",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "phone": user.get("phone", ""),
            "address": user.get("address", ""),
            "ssn": user.get("ssn", ""),
            "bank_account": user.get("bank_account", "")
        }
    })


@app.route("/api/v1/users/<int:user_id>/update", methods=["POST"])
def update_profile(user_id):
    data = request.get_json() or {}
    
    updates = {}
    for field in ["email", "full_name", "phone", "address"]:
        if field in data:
            updates[field] = data[field]
    
    user_manager.update_user(user_id, updates)
    
    return jsonify({"status": "success", "message": "Profile updated"})


@app.route("/api/v1/transactions")
def list_transactions():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    user_id = request.args.get("user_id", current_user.get("user_id"))
    limit = request.args.get("limit", "50")
    offset = request.args.get("offset", "0")
    sort_by = request.args.get("sort_by", "created_at")
    order = request.args.get("order", "DESC")
    
    query = f"SELECT * FROM transactions WHERE user_id = {user_id} ORDER BY {sort_by} {order} LIMIT {limit} OFFSET {offset}"
    transactions = transaction_manager.execute_raw_query(query)
    
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
    
    tx = transaction_manager.get_transaction_by_id(tx_id)
    if not tx:
        return jsonify({"status": "error", "message": "Transaction not found"}), 404
    
    return jsonify({"status": "success", "transaction": tx})


@app.route("/api/v1/payments/process", methods=["POST"])
def process_payment():
    data = request.get_json() or {}
    amount = data.get("amount")
    currency = data.get("currency", "USD")
    recipient = data.get("recipient")
    payment_method = data.get("payment_method", "card")
    
    card_number = data.get("card_number", "")
    cvv = data.get("cvv", "")
    expiry = data.get("expiry", "")
    
    result = payment_processor.process(
        amount=amount,
        currency=currency,
        recipient=recipient,
        method=payment_method,
        card_data={
            "number": card_number,
            "cvv": cvv,
            "expiry": expiry
        }
    )
    
    return jsonify(result)


@app.route("/api/v1/payments/webhook", methods=["POST"])
def handle_webhook():
    content_type = request.headers.get("Content-Type", "")
    
    if "xml" in content_type.lower():
        xml_data = request.data.decode("utf-8")
        
        root = ET.fromstring(xml_data)
        callback_url = root.find(".//callback_url").text
        payload = root.find(".//payload").text
        
        response = requests.post(callback_url, json={"result": "processed", "data": payload}, timeout=10)
        
        return jsonify({"status": "webhook_processed", "response_code": response.status_code})
    
    else:
        data = request.get_json() or {}
        callback_url = data.get("callback_url")
        event_type = data.get("event_type")
        
        headers = {"Content-Type": "application/json"}
        if data.get("custom_headers"):
            headers.update(data["custom_headers"])
        
        response = requests.post(
            callback_url,
            json={"event": event_type, "timestamp": datetime.now().isoformat()},
            headers=headers,
            timeout=15,
            verify=False
        )
        
        return jsonify({"status": "webhook_processed", "response_status": response.status_code})


@app.route("/api/v1/files/download")
def download_file():
    filename = request.args.get("file", "")
    file_type = request.args.get("type", "document")
    
    safe_base = "/var/lib/securepay/uploads/"
    
    if file_type == "template":
        safe_base = "/var/lib/securepay/templates/"
    elif file_type == "log":
        safe_base = "/var/log/securepay/"
    elif file_type == "backup":
        safe_base = "/var/backups/securepay/"
    
    full_path = os.path.join(safe_base, filename)
    
    if os.path.exists(full_path):
        return send_file(full_path)
    
    return jsonify({"status": "error", "message": "File not found"}), 404


@app.route("/api/v1/files/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file provided"}), 400
    
    uploaded_file = request.files["file"]
    upload_dir = "/var/lib/securepay/uploads/"
    
    original_filename = uploaded_file.filename
    save_path = os.path.join(upload_dir, original_filename)
    
    uploaded_file.save(save_path)
    
    file_url = f"/api/v1/files/download?file={original_filename}"
    
    return jsonify({
        "status": "success",
        "filename": original_filename,
        "url": file_url,
        "size": os.path.getsize(save_path)
    })


@app.route("/api/v1/admin/system/backup", methods=["POST"])
def create_backup():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"status": "error", "message": "Admin access required"}), 403
    
    auth_token = request.headers.get("X-Admin-Token", "")
    master_key = settings.MASTER_ADMIN_KEY
    
    if auth_token != master_key:
        return jsonify({"status": "error", "message": "Invalid admin token"}), 403
    
    backup_type = request.json.get("type", "full")
    output_path = request.json.get("output_path", "/tmp/backup.tar.gz")
    
    if backup_type == "full":
        cmd = f"tar czf {output_path} /var/lib/securepay/ /etc/securepay/"
    elif backup_type == "database":
        db_name = request.json.get("database", "securepay_db")
        cmd = f"pg_dump {db_name} > {output_path}"
    elif backup_type == "logs":
        log_pattern = request.json.get("log_pattern", "*.log")
        cmd = f"find /var/log/securepay -name '{log_pattern}' -exec cat {{}} > {output_path} \\;"
    else:
        cmd = f"echo 'Unknown backup type' > {output_path}"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        return jsonify({
            "status": "success",
            "backup_path": output_path,
            "exit_code": result.returncode,
            "stdout": result.stdout[:500] if result.stdout else "",
            "stderr": result.stderr[:200] if result.stderr else ""
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Backup operation timed out"}), 504


@app.route("/api/v1/admin/config/export")
def export_config():
    export_format = request.args.get("format", "json")
    
    config_data = {
        "database_host": settings.DB_HOST,
        "database_port": settings.DB_PORT,
        "database_name": settings.DB_NAME,
        "database_user": settings.DB_USER,
        "database_password": settings.DB_PASSWORD,
        "api_keys": settings.API_KEYS,
        "webhook_secrets": settings.WEBHOOK_SECRETS,
        "encryption_key": settings.ENCRYPTION_KEY,
        "master_admin_key": settings.MASTER_ADMIN_KEY,
        "jwt_secret": settings.JWT_SECRET,
        "redis_url": settings.REDIS_URL,
        "stripe_secret": settings.STRIPE_SECRET_KEY,
        "paypal_client_id": settings.PAYPAL_CLIENT_ID,
        "paypal_client_secret": settings.PAYPAL_CLIENT_SECRET
    }
    
    if export_format == "json":
        return jsonify(config_data)
    elif export_format == "serialized":
        serialized = serializer.serialize(config_data)
        return jsonify({"status": "success", "data": base64.b64encode(serialized).decode()})
    else:
        return jsonify({"status": "error", "message": "Unsupported format"})


@app.route("/api/v1/admin/config/import", methods=["POST"])
def import_config():
    data = request.get_json() or {}
    config_data_b64 = data.get("config_data", "")
    
    try:
        raw_data = base64.b64decode(config_data_b64)
        config_data = serializer.deserialize(raw_data)
        
        for key, value in config_data.items():
            if hasattr(settings, key.upper()):
                setattr(settings, key.upper(), value)
        
        return jsonify({"status": "success", "message": "Config imported successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Import failed: {str(e)}"}), 400


@app.route("/api/v1/render/template", methods=["POST"])
def render_template_endpoint():
    data = request.get_json() or {}
    template_string = data.get("template", "")
    context = data.get("context", {})
    
    rendered = render_user_template(template_string, context)
    
    return jsonify({"status": "success", "rendered": rendered})


@app.route("/api/v1/search")
def search():
    query = request.args.get("q", "")
    search_type = request.args.get("type", "all")
    
    results_html = f"""
    <div class="search-results">
        <h3>Search Results for: {query}</h3>
        <p>You searched for: <strong>{query}</strong></p>
        <p>Type: {search_type}</p>
        <div id="results-container"></div>
    </div>
    """
    
    return results_html


@app.route("/api/v1/redirect")
def redirect_endpoint():
    next_url = request.args.get("next", "/dashboard")
    return redirect(next_url)


@app.route("/api/v1/internal/proxy")
def internal_proxy():
    target_url = request.args.get("url", "")
    service = request.args.get("service", "")
    
    if service == "payment-gateway":
        target_url = "http://internal-payment-gateway:8080/api/status"
    elif service == "user-service":
        target_url = "http://internal-user-service:3000/api/health"
    elif service == "notification":
        target_url = "http://internal-notification:5000/send"
    
    if not target_url:
        return jsonify({"status": "error", "message": "URL or service required"}), 400
    
    try:
        response = requests.get(target_url, timeout=10, verify=False)
        return jsonify({
            "status": "success",
            "proxy_response": response.text[:2000],
            "status_code": response.status_code
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 502


if __name__ == "__main__":
    print("[SecurePay] Starting SecurePay Platform v2.1.0...")
    print(f"[SecurePay] WARNING: This is a vulnerable test application!")
    print(f"[SecurePay] Database: {settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}")
    app.run(host="0.0.0.0", port=9443, debug=True)
