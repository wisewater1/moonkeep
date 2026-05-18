import hashlib
import hmac
import os
import sys
import time
import sqlite3
import secrets
from typing import Optional

import jwt
import bcrypt
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = os.environ.get("MOONKEEP_SECRET_KEY", secrets.token_hex(32))
TOKEN_EXPIRY = int(os.environ.get("MOONKEEP_TOKEN_EXPIRY", "86400"))
AUTH_DB = os.environ.get("MOONKEEP_AUTH_DB", "moonkeep_auth.db")
ALGORITHM = "HS256"
DEFAULT_PASSWORD_FILE = os.environ.get(
    "MOONKEEP_INITIAL_PASSWORD_FILE", "/var/lib/moonkeep/initial-password.txt"
)

security = HTTPBearer(auto_error=False)


def _conn():
    conn = sqlite3.connect(AUTH_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_auth_db():
    with _conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'operator',
            created_at REAL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            endpoint TEXT,
            method TEXT,
            ip TEXT,
            timestamp REAL
        )""")
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            password = _resolve_initial_admin_password()
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("admin", pw_hash, "admin", time.time()),
            )


def _resolve_initial_admin_password() -> str:
    """Pick the initial admin password.

    Priority:
      1. MOONKEEP_ADMIN_PASSWORD env var (tests + scripted installs use this).
      2. Random secrets.token_urlsafe(16), persisted to DEFAULT_PASSWORD_FILE
         with mode 0600 and announced once on stderr.
    """
    explicit = os.environ.get("MOONKEEP_ADMIN_PASSWORD")
    if explicit:
        print(
            "[AUTH] Default admin user created (password from MOONKEEP_ADMIN_PASSWORD)",
            file=sys.stderr,
        )
        return explicit

    password = secrets.token_urlsafe(16)
    try:
        os.makedirs(os.path.dirname(DEFAULT_PASSWORD_FILE) or ".", exist_ok=True)
        # O_CREAT|O_WRONLY|O_TRUNC + 0o600 — never world-readable.
        fd = os.open(DEFAULT_PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(password + "\n")
        print(
            f"[AUTH] Default admin user created with RANDOM password — read it from "
            f"{DEFAULT_PASSWORD_FILE} (mode 0600)",
            file=sys.stderr,
        )
    except OSError as exc:
        # Fall back to stderr-only if the path isn't writable (e.g. unprivileged
        # local dev). The password is still secure, just less discoverable.
        print(
            f"[AUTH] Could not write {DEFAULT_PASSWORD_FILE} ({exc}). "
            f"Initial admin password: {password}",
            file=sys.stderr,
        )
    return password


def create_user(username: str, password: str, role: str = "operator") -> dict:
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with _conn() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, pw_hash, role, time.time()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Username already exists")
    return {"username": username, "role": role}


def authenticate(username: str, password: str) -> Optional[dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username=?",
            (username,),
        ).fetchone()
    if not row:
        return None
    if bcrypt.checkpw(password.encode(), row[2].encode()):
        return {"id": row[0], "username": row[1], "role": row[3]}
    return None


def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": time.time() + TOKEN_EXPIRY,
        "iat": time.time(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except jwt.PyJWTError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"username": payload["sub"], "role": payload["role"]}


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def log_audit(username: str, action: str, endpoint: str, method: str, ip: str):
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (username, action, endpoint, method, ip, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (username, action, endpoint, method, ip, time.time()),
            )
    except Exception:
        pass


def get_audit_log(limit: int = 100) -> list:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT username, action, endpoint, method, ip, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {"username": r[0], "action": r[1], "endpoint": r[2], "method": r[3], "ip": r[4], "timestamp": r[5]}
        for r in rows
    ]


def list_users() -> list:
    with _conn() as conn:
        rows = conn.execute("SELECT id, username, role, created_at FROM users").fetchall()
    return [{"id": r[0], "username": r[1], "role": r[2], "created_at": r[3]} for r in rows]


def change_password(username: str, old_password: str, new_password: str) -> bool:
    user = authenticate(username, old_password)
    if not user:
        return False
    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    with _conn() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE username=?", (pw_hash, username))
    return True


def delete_user(username: str):
    with _conn() as conn:
        conn.execute("DELETE FROM users WHERE username=?", (username,))
