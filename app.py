"""
Sistema Principal - Autenticación 2FA + Integridad de Mensajes
Ingeniería de Software II - Seguridad como Atributo de Calidad
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import bcrypt
import pyotp
import qrcode
from flask import render_template
import io
import base64
import hashlib
import hmac
import json
import time
import uuid
from flask import send_from_directory
import os
import os
from datetime import datetime

app = Flask(__name__, 
            static_folder='frontend/static',
            template_folder='frontend/templates')
CORS(app)

# ─── CLAVE SECRETA COMPARTIDA PARA HMAC (sistema A ↔ sistema B) ────────────
SHARED_SECRET = "clave-secreta-compartida-2024-IS2"

# ─── BASE DE DATOS EN MEMORIA ────────────────────────────────────────────────
users_db = {}          # { username: { password_hash, totp_secret, name } }
sessions_db = {}       # { session_token: { username, step, expires } }
messages_log = []      # historial de mensajes entre sistemas

# ─── MÓDULO DE AUTENTICACIÓN ─────────────────────────────────────────────────

class AuthModule:
    """Lógica de autenticación de credenciales (Factor 1)"""

    @staticmethod
    def register_user(username: str, password: str, name: str) -> dict:
        if username in users_db:
            return {"ok": False, "error": "Usuario ya existe"}
        
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode(), salt)
        totp_secret = pyotp.random_base32()
        
        users_db[username] = {
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "name": name,
            "created_at": datetime.now().isoformat()
        }
        return {"ok": True, "totp_secret": totp_secret}

    @staticmethod
    def validate_credentials(username: str, password: str) -> bool:
        user = users_db.get(username)
        if not user:
            return False
        return bcrypt.checkpw(password.encode(), user["password_hash"])


class TwoFactorModule:
    """Lógica del segundo factor de autenticación (TOTP - RFC 6238)"""

    @staticmethod
    def get_qr_code(username: str) -> str:
        user = users_db.get(username)
        if not user:
            return None
        totp = pyotp.TOTP(user["totp_secret"])
        uri = totp.provisioning_uri(name=username, issuer_name="SecureSystem-IS2")
        
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()

    @staticmethod
    def validate_totp(username: str, token: str) -> bool:
        user = users_db.get(username)
        if not user:
            return False
        totp = pyotp.TOTP(user["totp_secret"])
        return totp.verify(token, valid_window=1)


class SessionModule:
    """Gestión de sesiones con flujo de 2 pasos"""

    @staticmethod
    def create_pending_session(username: str) -> str:
        token = str(uuid.uuid4())
        sessions_db[token] = {
            "username": username,
            "step": "awaiting_2fa",
            "expires": time.time() + 300  # 5 min para completar 2FA
        }
        return token

    @staticmethod
    def complete_session(token: str) -> str:
        session = sessions_db.get(token)
        if not session or session["step"] != "awaiting_2fa":
            return None
        if time.time() > session["expires"]:
            del sessions_db[token]
            return None
        
        final_token = str(uuid.uuid4())
        sessions_db[final_token] = {
            "username": session["username"],
            "step": "authenticated",
            "expires": time.time() + 3600
        }
        del sessions_db[token]
        return final_token

    @staticmethod
    def validate_session(token: str) -> dict:
        session = sessions_db.get(token)
        if not session or session["step"] != "authenticated":
            return None
        if time.time() > session["expires"]:
            del sessions_db[token]
            return None
        return session


# ─── MÓDULO DE INTEGRIDAD DE MENSAJES ────────────────────────────────────────

class IntegrityModule:
    """Generación y verificación de huellas HMAC-SHA256"""

    @staticmethod
    def sign_message(payload: dict) -> dict:
        """Agrega timestamp, ID y firma HMAC al mensaje"""
        msg = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "payload": payload
        }
        body = json.dumps(msg, sort_keys=True)
        signature = hmac.new(
            SHARED_SECRET.encode(),
            body.encode(),
            hashlib.sha256
        ).hexdigest()
        
        msg["signature"] = signature
        msg["hash_preview"] = signature[:16] + "..."
        return msg

    @staticmethod
    def verify_message(msg: dict) -> dict:
        """Verifica la integridad del mensaje recibido"""
        try:
            sig_received = msg.get("signature")
            msg_to_verify = {k: v for k, v in msg.items() if k != "signature" and k != "hash_preview"}
            body = json.dumps(msg_to_verify, sort_keys=True)
            
            sig_expected = hmac.new(
                SHARED_SECRET.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            
            is_valid = hmac.compare_digest(sig_received, sig_expected)
            return {
                "valid": is_valid,
                "signature_received": sig_received,
                "signature_expected": sig_expected,
                "match": is_valid
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}


# ─── INSTANCIAS DE MÓDULOS ───────────────────────────────────────────────────
auth = AuthModule()
totp_mod = TwoFactorModule()
sessions = SessionModule()
integrity = IntegrityModule()


# ─── ENDPOINTS DE AUTENTICACIÓN ──────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    name = data.get("name", username)
    
    if not username or not password:
        return jsonify({"ok": False, "error": "Datos incompletos"}), 400
    
    result = auth.register_user(username, password, name)
    if result["ok"]:
        qr = totp_mod.get_qr_code(username)
        result["qr_code"] = qr
        result["message"] = "Usuario registrado. Escanea el QR con Google Authenticator."
    return jsonify(result), 201 if result["ok"] else 400


@app.route("/api/auth/login", methods=["POST"])
def login_step1():
    """Paso 1: Validar usuario y contraseña"""
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    log_event("LOGIN_ATTEMPT", username, {"step": 1})
    
    if not auth.validate_credentials(username, password):
        log_event("LOGIN_FAILED", username, {"reason": "credenciales_invalidas"})
        return jsonify({"ok": False, "error": "Credenciales incorrectas"}), 401
    
    pending_token = sessions.create_pending_session(username)
    log_event("LOGIN_STEP1_OK", username, {"step": 1})
    
    return jsonify({
        "ok": True,
        "pending_token": pending_token,
        "message": "Credenciales válidas. Ingresa tu código 2FA.",
        "user_name": users_db[username]["name"]
    })


@app.route("/api/auth/verify-2fa", methods=["POST"])
def login_step2():
    """Paso 2: Validar código TOTP"""
    data = request.json
    pending_token = data.get("pending_token", "")
    totp_code = data.get("totp_code", "").strip()
    
    session = sessions_db.get(pending_token)
    if not session or session["step"] != "awaiting_2fa":
        return jsonify({"ok": False, "error": "Sesión pendiente inválida o expirada"}), 401
    
    username = session["username"]
    log_event("2FA_ATTEMPT", username, {"step": 2})
    
    if not totp_mod.validate_totp(username, totp_code):
        log_event("2FA_FAILED", username, {"reason": "codigo_invalido"})
        return jsonify({"ok": False, "error": "Código 2FA incorrecto"}), 401
    
    final_token = sessions.complete_session(pending_token)
    log_event("LOGIN_SUCCESS", username, {"step": 2})
    
    return jsonify({
        "ok": True,
        "session_token": final_token,
        "username": username,
        "name": users_db[username]["name"],
        "message": "Autenticación completa. Acceso permitido."
    })


@app.route("/api/auth/demo-totp", methods=["GET"])
def demo_totp():
    """Solo para demo — devuelve el código TOTP actual del usuario"""
    username = request.args.get("username", "")
    user = users_db.get(username)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    totp = pyotp.TOTP(user["totp_secret"])
    return jsonify({"code": totp.now(), "username": username})


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    session = sessions.validate_session(token)
    if not session:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "username": session["username"]})


# ─── ENDPOINTS DE MENSAJERÍA CON INTEGRIDAD ──────────────────────────────────

@app.route("/api/messages/send", methods=["POST"])
def send_message():
    """Sistema A envía mensaje firmado a Sistema B"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    session = sessions.validate_session(token)
    if not session:
        return jsonify({"ok": False, "error": "No autenticado"}), 401
    
    data = request.json
    content = data.get("content", "").strip()
    tamper = data.get("tamper", False)  # para demostración: alterar el mensaje
    
    if not content:
        return jsonify({"ok": False, "error": "Mensaje vacío"}), 400
    
    payload = {
        "from": session["username"],
        "content": content,
        "system": "Sistema A"
    }
    
    signed_msg = integrity.sign_message(payload)
    
    # Simular alteración del mensaje (escenario de demostración)
    tampered_content = data.get("tampered_content", "").strip()
    if tamper and tampered_content:
        signed_msg["payload"]["content"] = tampered_content
    elif tamper:
        signed_msg["payload"]["content"] = content + " [ALTERADO]"  
    
    # Simular recepción en Sistema B
    verification = integrity.verify_message(
        {k: v for k, v in signed_msg.items() if k != "hash_preview"}
    )
    
    log_entry = {
        "id": signed_msg["id"],
        "timestamp": signed_msg["timestamp"],
        "from": session["username"],
        "content": signed_msg["payload"]["content"],
        "original_content": content,
        "tampered": tamper,
        "signature": signed_msg["signature"],
        "hash_preview": signed_msg["hash_preview"],
        "verification": verification
    }
    messages_log.append(log_entry)
    
    return jsonify({
        "ok": True,
        "message_id": signed_msg["id"],
        "signed_message": signed_msg,
        "verification_result": verification,
        "accepted": verification["valid"],
        "status": "ACEPTADO ✓" if verification["valid"] else "RECHAZADO ✗"
    })


@app.route("/api/messages/log", methods=["GET"])
def get_messages():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    session = sessions.validate_session(token)
    if not session:
        return jsonify({"ok": False, "error": "No autenticado"}), 401
    return jsonify({"ok": True, "messages": messages_log[-20:]})


# ─── UTILS ───────────────────────────────────────────────────────────────────

def log_event(event_type, username, details):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {event_type} | user={username} | {details}")


@app.route("/api/users/list", methods=["GET"])
def list_users():
    """Para demostración - lista usuarios registrados"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    session = sessions.validate_session(token)
    if not session:
        return jsonify({"ok": False, "error": "No autenticado"}), 401
    
    users = [{"username": u, "name": d["name"], "created_at": d["created_at"]} 
             for u, d in users_db.items()]
    return jsonify({"ok": True, "users": users})


# ─── SEED DE USUARIOS DEMO ───────────────────────────────────────────────────

def seed_demo_users():
    auth.register_user("admin", "admin123", "Administrador")
    auth.register_user("usuario1", "pass123", "María García")
    print("=" * 60)
    print("USUARIOS DEMO CREADOS:")
    print("  admin / admin123")
    print("  usuario1 / pass123")
    print("TOTP secrets (para usar en autenticador):")
    for u, d in users_db.items():
        totp = pyotp.TOTP(d["totp_secret"])
        print(f"  {u}: {d['totp_secret']} | código actual: {totp.now()}")
    print("=" * 60)


# ─── SERVIR FRONTEND ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    seed_demo_users()
    app.run(debug=True, port=5000, use_reloader=False)