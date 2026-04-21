"""
sample_targets/clean_app.py
Secure implementation of the same functionality as vulnerable_app.py.
Used to verify the scanner doesn't produce false positives.
"""

import os
import sqlite3
import subprocess
import hashlib
import hmac
import secrets
import shlex
import yaml
from pathlib import Path


def get_user(username: str):
    """Parameterised query — immune to SQL injection."""
    conn   = sqlite3.connect("users.db")
    query  = "SELECT * FROM users WHERE username = ?"
    result = conn.execute(query, (username,))
    return result.fetchall()


def search_products(search_term: str, category: str):
    """Parameterised query with multiple parameters."""
    conn = sqlite3.connect("products.db")
    sql  = "SELECT * FROM products WHERE name LIKE ? AND category = ?"
    return conn.execute(sql, (f"%{search_term}%", category)).fetchall()


def run_diagnostic(host: str):
    """
    Safe subprocess call — no shell=True, arguments passed as list.
    Input validated against an allowlist.
    """
    # Validate host is a safe hostname/IP — no shell metacharacters
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")
    if not all(c in allowed for c in host.lower()):
        raise ValueError(f"Invalid host: {host}")

    result = subprocess.run(
        ["ping", "-c", "4", host],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout


def read_log_file(filename: str):
    """
    Safe file read — resolves path and checks it stays within log directory.
    Prevents path traversal.
    """
    log_dir  = Path("/var/log/app/").resolve()
    safe_path = (log_dir / filename).resolve()

    # Ensure the resolved path is still within the log directory
    if not str(safe_path).startswith(str(log_dir)):
        raise PermissionError(f"Access denied: {filename}")

    return safe_path.read_text()


def hash_password(password: str) -> str:
    """
    Secure password hashing using PBKDF2-HMAC-SHA256.
    MD5 is not used — it is cryptographically broken for passwords.
    """
    salt   = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time comparison prevents timing attacks."""
    salt_hex, digest_hex = stored_hash.split(":")
    salt   = bytes.fromhex(salt_hex)
    stored = bytes.fromhex(digest_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return hmac.compare_digest(candidate, stored)


def get_config(config_file: str):
    """Safe YAML loading with explicit Loader to prevent code execution."""
    with open(config_file) as f:
        return yaml.safe_load(f.read())


def delete_user(user_id: int):
    """Parameterised DELETE — type-enforced integer ID."""
    if not isinstance(user_id, int):
        raise TypeError("user_id must be an integer")
    conn = sqlite3.connect("users.db")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


def update_profile(user_id: int, data: dict):
    """
    Explicit allowlist of updatable fields — prevents mass assignment.
    """
    ALLOWED_FIELDS = {"display_name", "bio", "avatar_url", "email"}
    safe_data = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}

    if not safe_data:
        return

    conn = sqlite3.connect("users.db")
    sets = ", ".join(f"{k} = ?" for k in safe_data.keys())
    sql  = f"UPDATE users SET {sets} WHERE id = ?"
    conn.execute(sql, list(safe_data.values()) + [user_id])
    conn.commit()


def store_session(session_id: str, user_id: int, display_name: str):
    """
    Stores only non-sensitive session data.
    Passwords and card numbers never written to disk.
    """
    session = {
        "session_id":   session_id,
        "user_id":      user_id,
        "display_name": display_name,
    }
    import json
    session_dir = Path("/tmp/sessions/")
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / f"{session_id}.json").write_text(json.dumps(session))