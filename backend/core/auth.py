import hashlib
import hmac
import os
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
            pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("admin", pw_hash, "admin", time.time()),
            )
            print("[AUTH] Default admin user created (username: admin, password: admin)")


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
