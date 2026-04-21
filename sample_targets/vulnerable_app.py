"""
sample_targets/vulnerable_app.py
Intentionally vulnerable Python application for testing llm-vuln-scan.
Contains real vulnerability patterns across multiple CWE categories.

DO NOT deploy this code anywhere. For testing purposes only.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
import yaml


# CWE-798: Hardcoded credentials
DB_PASSWORD   = "admin123"
SECRET_KEY    = "hardcoded_secret_key_do_not_use"
API_KEY       = "sk-prod-abc123xyz789"


def get_user(username: str):
    """CWE-89: SQL Injection — user input directly concatenated into query."""
    conn  = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    result = conn.execute(query)
    return result.fetchall()


def search_products(search_term: str, category: str):
    """CWE-89: SQL Injection in multiple parameters."""
    conn = sqlite3.connect("products.db")
    sql  = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' AND category = '{category}'"
    return conn.execute(sql).fetchall()


def run_diagnostic(host: str):
    """CWE-78: OS Command Injection — shell=True with user input."""
    output = subprocess.run(
        f"ping -c 4 {host}",
        shell=True,
        capture_output=True,
        text=True
    )
    return output.stdout


def read_log_file(filename: str):
    """CWE-22: Path Traversal — no sanitisation of filename."""
    log_dir = "/var/log/app/"
    with open(log_dir + filename, "r") as f:
        return f.read()


def load_user_data(serialised_data: bytes):
    """CWE-502: Insecure Deserialization — unpickling untrusted data."""
    return pickle.loads(serialised_data)


def hash_password(password: str) -> str:
    """CWE-327: Weak cryptography — MD5 is cryptographically broken."""
    return hashlib.md5(password.encode()).hexdigest()


def get_config(config_file: str):
    """CWE-20: Improper input validation — yaml.load without Loader."""
    with open(config_file) as f:
        return yaml.load(f.read())


def delete_user(user_id: str):
    """CWE-89: SQL Injection in DELETE statement."""
    conn  = sqlite3.connect("users.db")
    query = "DELETE FROM users WHERE id = " + user_id
    conn.execute(query)
    conn.commit()


def update_profile(user_id: int, data: dict):
    """
    CWE-915: Mass assignment — blindly applies all fields from user input.
    An attacker can set is_admin=True or role=superuser.
    """
    conn = sqlite3.connect("users.db")
    sets = ", ".join(f"{k} = ?" for k in data.keys())
    sql  = f"UPDATE users SET {sets} WHERE id = ?"
    conn.execute(sql, list(data.values()) + [user_id])
    conn.commit()


def execute_report(report_name: str):
    """CWE-78: Command injection via report name parameter."""
    os.system(f"python reports/{report_name}.py")


def store_session(session_id: str, user_data: dict):
    """
    CWE-200: Sensitive data exposure — stores password in session.
    """
    session = {
        "session_id": session_id,
        "user":       user_data,
        "password":   user_data.get("password"),   # never store passwords in sessions
        "credit_card": user_data.get("credit_card"),
    }
    with open(f"/tmp/sessions/{session_id}.pkl", "wb") as f:
        pickle.dump(session, f)