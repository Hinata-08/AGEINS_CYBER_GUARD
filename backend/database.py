import sqlite3
import json
import hashlib
import secrets
import time
import os
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "ageins.db")
SESSION_EXPIRE_DAYS = 7

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def pwhash(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000).hex()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Scans Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT DEFAULT 'guest_user',
        scan_type TEXT NOT NULL,
        target_preview TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        verdict TEXT NOT NULL,
        sources_checked TEXT NOT NULL,
        details_json TEXT NOT NULL,
        quarantined INTEGER DEFAULT 0,
        privacy_protected INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. Users Table Schema Migration
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT UNIQUE)")
    cursor.execute("PRAGMA table_info(users)")
    existing_cols = {col["name"] for col in cursor.fetchall()}

    needed_cols = {
        "salt": "TEXT NOT NULL DEFAULT ''",
        "hash": "TEXT NOT NULL DEFAULT ''",
        "role": "TEXT NOT NULL DEFAULT 'user'",
        "status": "TEXT DEFAULT 'active'",
        "spent": "INTEGER DEFAULT 0",
        "created_at": "REAL",
        "last_login": "REAL"
    }

    for col_name, col_def in needed_cols.items():
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

    # 3. User Sessions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        uid INTEGER NOT NULL,
        last_seen REAL NOT NULL,
        FOREIGN KEY(uid) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 4. Admin Configurations
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admin_configs (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        description TEXT,
        category TEXT DEFAULT 'general',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 5. Multi-Source Detection Engines
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detection_engines (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        threat_count INTEGER DEFAULT 0,
        last_sync TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 6. Audit Log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Seed / Update Default Organiser Admin Account
    admin_email = os.getenv("ADMIN_EMAIL", "admin@ageins.com")
    salt = secrets.token_hex(16)
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    pwd_hash = pwhash(admin_pass, salt)
    now = time.time()

    cursor.execute("SELECT id FROM users WHERE email = ?", (admin_email,))
    existing_admin = cursor.fetchone()

    if not existing_admin:
        cursor.execute("""
        INSERT INTO users (username, email, salt, hash, role, status, created_at, last_login)
        VALUES (?, ?, ?, ?, 'admin', 'active', ?, ?)
        """, ("Organiser Admin", admin_email, salt, pwd_hash, now, now))
    else:
        cursor.execute("""
        UPDATE users SET salt = ?, hash = ?, role = 'admin', status = 'active' WHERE email = ?
        """, (salt, pwd_hash, admin_email))

    # Seed Default Configurations if empty
    cursor.execute("SELECT COUNT(*) FROM admin_configs")
    if cursor.fetchone()[0] == 0:
        default_configs = [
            ("detection_sensitivity", "high", "Threat heuristic sensitivity level", "detection"),
            ("deepfake_spectral_threshold", "72", "Spectral anomaly cutoff threshold for AI images/video", "detection"),
            ("privacy_shield_mode", "strict", "Client data anonymization and immediate memory flush", "security"),
            ("auto_quarantine_score", "65", "Risk score threshold at which threats are quarantined automatically", "control"),
            ("multi_source_aggregation", "enabled", "Aggregate results across all active intelligence engines", "detection"),
            ("data_retention_days", "30", "Days before raw scan logs are securely scrubbed", "compliance")
        ]
        cursor.executemany("INSERT INTO admin_configs (key, value, description, category) VALUES (?, ?, ?, ?)", default_configs)

    # Seed Detection Engines
    cursor.execute("SELECT COUNT(*) FROM detection_engines")
    if cursor.fetchone()[0] == 0:
        default_engines = [
            ("ageins_neural", "AGEINS Deep Neural Heuristics", "AI Pattern Analysis", "active", 1420),
            ("spectral_ela", "Spectral FFT & ELA Forensic Engine", "Image/Video Forensics", "active", 980),
            ("acoustic_asv", "Acoustic ASVspoof Pitch Analysis", "Audio Forensics", "active", 430),
            ("global_threat_feed", "Global PhishTank & URLhaus Feeds", "Threat Intelligence", "active", 4890),
            ("trust_mismatch_engine", "Trust Mismatch Cross-Modal Detector", "Deepfake Forensics", "active", 760),
            ("payment_qr_scanner", "Payment QR Code & Fake Gateway Detector", "Financial Security", "active", 890),
            ("bank_fraud_detector", "Fraud Bank Details & IFSC Inspector", "Financial Security", "active", 1120),
            ("phone_fraud_detector", "Fraud Phone Number & SMS Detector", "Telecom Telemetry", "active", 1540)
        ]
        cursor.executemany("INSERT INTO detection_engines (id, name, source_type, status, threat_count) VALUES (?, ?, ?, ?, ?)", default_engines)

    conn.commit()
    conn.close()

def register_user(username: str, email: str, password: str, role: str = "user") -> Dict[str, Any]:
    email_clean = email.strip().lower()
    username_base = username.strip() or email_clean.split("@")[0]
    username_clean = username_base
    
    if "@" not in email_clean or len(password) < 6:
        raise ValueError("Enter a valid email address and a password of at least 6 characters.")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE email = ?", (email_clean,))
    if cursor.fetchone():
        conn.close()
        raise ValueError("This email address is already registered.")

    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username_clean,))
    if cursor.fetchone():
        username_clean = f"{username_base} #{secrets.token_hex(2)}"

    salt = secrets.token_hex(16)
    pwd_hash = pwhash(password, salt)
    now = time.time()

    cursor.execute("""
    INSERT INTO users (username, email, salt, hash, role, status, created_at, last_login)
    VALUES (?, ?, ?, ?, 'user', 'active', ?, ?)
    """, (username_clean, email_clean, salt, pwd_hash, now, now))
    
    uid = cursor.lastrowid
    token = secrets.token_urlsafe(32)
    cursor.execute("INSERT INTO sessions (token, uid, last_seen) VALUES (?, ?, ?)", (token, uid, now))
    conn.commit()
    
    cursor.execute("SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?", (uid,))
    user_row = dict(cursor.fetchone())
    conn.close()
    
    return {"token": token, "user": user_row}

def login_user(email: str, password: str) -> Dict[str, Any]:
    email_clean = email.strip().lower()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email_clean,))
    user = cursor.fetchone()

    if not user or not user["salt"] or pwhash(password, user["salt"]) != user["hash"]:
        conn.close()
        raise ValueError("Incorrect email address or password.")

    if user["status"] == "suspended":
        conn.close()
        raise ValueError("Account suspended. Contact the Organiser.")

    now = time.time()
    token = secrets.token_urlsafe(32)
    cursor.execute("INSERT INTO sessions (token, uid, last_seen) VALUES (?, ?, ?)", (token, user["id"], now))
    cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user["id"]))
    conn.commit()

    user_dict = {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"],
        "last_login": user["last_login"]
    }
    conn.close()
    return {"token": token, "user": user_dict}

def verify_token(token: str) -> Dict[str, Any]:
    if not token:
        raise ValueError("Missing session token.")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT u.id, u.username, u.email, u.role, u.status, s.last_seen
    FROM sessions s JOIN users u ON u.id = s.uid
    WHERE s.token = ?
    """, (token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise ValueError("Session token invalid or expired.")

    if time.time() - row["last_seen"] > SESSION_EXPIRE_DAYS * 86400:
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        raise ValueError("Session expired. Please sign in again.")

    user_dict = dict(row)
    conn.close()
    return user_dict

def ping_session(token: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT uid, last_seen FROM sessions WHERE token = ?", (token,))
    s = cursor.fetchone()
    if not s:
        conn.close()
        return False

    now = time.time()
    add_sec = int(min(max(now - s["last_seen"], 0), 60))
    cursor.execute("UPDATE users SET spent = spent + ? WHERE id = ?", (add_sec, s["uid"]))
    cursor.execute("UPDATE sessions SET last_seen = ? WHERE token = ?", (now, token))
    conn.commit()
    conn.close()
    return True

def get_organiser_users_data() -> List[Dict[str, Any]]:
    """Organiser side access ONLY: Returns all registered users' login and activity data."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT u.id, u.username, u.email, u.role, u.status, u.created_at, u.last_login, u.spent,
           (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.email OR s.user_id = CAST(u.id AS TEXT)) AS total_scans
    FROM users u
    ORDER BY u.created_at DESC
    """)
    users = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return users

def delete_user_by_admin(uid: int, admin_uid: int) -> bool:
    if uid == admin_uid:
        raise ValueError("Organiser cannot delete their own active admin account.")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE uid = ?", (uid,))
    cursor.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return True

def log_audit(actor: str, action: str, target: str, details: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO audit_logs (actor, action, target, details) VALUES (?, ?, ?, ?)", (actor, action, target, details))
    conn.commit()
    conn.close()

def save_scan_result(user_id: str, scan_type: str, target_preview: str, risk_score: int, risk_level: str, verdict: str, sources: List[str], details: Dict[str, Any], quarantined: bool = False) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    
    content_hash = hashlib.sha256(target_preview.encode('utf-8', errors='ignore')).hexdigest()
    
    cursor.execute("SELECT value FROM admin_configs WHERE key = 'auto_quarantine_score'")
    row = cursor.fetchone()
    auto_thresh = int(row[0]) if row else 65
    is_quarantined = 1 if (quarantined or risk_score >= auto_thresh) else 0

    cursor.execute("""
    INSERT INTO scans (user_id, scan_type, target_preview, content_hash, risk_score, risk_level, verdict, sources_checked, details_json, quarantined, privacy_protected)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, (user_id, scan_type, target_preview[:120], content_hash, risk_score, risk_level, verdict, json.dumps(sources), json.dumps(details), is_quarantined))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_user_dashboard(user_id: str = "guest_user") -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE user_id = ? OR user_id = 'guest_user' ORDER BY created_at DESC LIMIT 30", (user_id,))
    rows = cursor.fetchall()
    scans = [dict(r) for r in rows]

    total_scans = len(scans)
    threats_prevented = sum(1 for s in scans if s["risk_score"] >= 65)
    avg_threat_score = round(sum(s["risk_score"] for s in scans) / max(1, total_scans), 1)

    category_counts = {}
    for s in scans:
        st = s["scan_type"]
        category_counts[st] = category_counts.get(st, 0) + 1

    conn.close()
    return {
        "total_scans": total_scans,
        "threats_prevented": threats_prevented,
        "avg_threat_score": avg_threat_score,
        "category_counts": category_counts,
        "recent_scans": scans
    }

def get_admin_overview() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE quarantined = 1")
    total_quarantined = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_score >= 65")
    total_critical = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users")
    active_users = cursor.fetchone()[0]

    cursor.execute("SELECT * FROM admin_configs")
    configs = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM detection_engines")
    engines = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20")
    logs = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {
        "metrics": {
            "total_scans": total_scans,
            "total_quarantined": total_quarantined,
            "total_critical": total_critical,
            "active_users": active_users
        },
        "users": get_organiser_users_data(),
        "configs": {c["key"]: c["value"] for c in configs},
        "configs_full": configs,
        "engines": engines,
        "audit_logs": logs
    }

def update_config(key: str, value: str, actor: str = "Organiser Admin"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin_configs SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", (value, key))
    conn.commit()
    conn.close()
    log_audit(actor, "UPDATE_CONFIG", key, f"Updated value to '{value}'")

def toggle_quarantine(scan_id: int, quarantine_status: bool, actor: str = "Organiser Admin"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET quarantined = ? WHERE id = ?", (1 if quarantine_status else 0, scan_id))
    conn.commit()
    conn.close()
    log_audit(actor, "TOGGLE_QUARANTINE", f"Scan ID #{scan_id}", f"Set quarantine to {quarantine_status}")

def update_user_role(user_id: int, new_role: str, status: str = "active", actor: str = "Organiser Admin"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ?, status = ? WHERE id = ?", (new_role, status, user_id))
    conn.commit()
    conn.close()
    log_audit(actor, "UPDATE_USER_ROLE", f"User #{user_id}", f"Role: {new_role}, Status: {status}")

init_db()
