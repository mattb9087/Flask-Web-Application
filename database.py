"""SQLite database functions for the secure intranet"""

import sqlite3
from pathlib import Path
from typing import Any

from auth_utils import hash_password

DATABASE = Path("intranet.db")
DEFAULT_ACCESS_LEVEL = "employee"
MAX_LOGIN_ATTEMPTS = 3


def get_connection() -> sqlite3.Connection:
    """create and return an SQLite connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    """create the users table and seed default accounts if needed"""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                access_level TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.commit()

    seed_user("admin", "Admin123!", "admin")
    seed_user("accountant", "Account123!", "accounting")
    seed_user("engineer", "Engineer123!", "engineering")


def seed_user(username: str, password: str, access_level: str) -> None:
    """insert a default user only if it does not already exist"""
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT username FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, access_level, failed_attempts, locked)
                VALUES (?, ?, ?, 0, 0)
                """,
                (username, hash_password(password), access_level),
            )
            conn.commit()


def get_user(username: str) -> sqlite3.Row | None:
    """return a user by username using a parameterized query"""
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT username, password_hash, access_level, failed_attempts, locked
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()


def create_user(username: str, password_hash: str,
                access_level: str = DEFAULT_ACCESS_LEVEL) -> bool:
    """create a user and return False if the username already exists"""
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, access_level, failed_attempts, locked)
                VALUES (?, ?, ?, 0, 0)
                """,
                (username, password_hash, access_level),
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def increment_failed_attempts(username: str) -> int:
    """increase failed login attempts and lock account after 3 failures"""
    user = get_user(username)
    if user is None:
        return 0

    attempts = int(user["failed_attempts"]) + 1
    locked = 1 if attempts >= MAX_LOGIN_ATTEMPTS else 0

    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET failed_attempts = ?, locked = ?
            WHERE username = ?
            """,
            (attempts, locked, username),
        )
        conn.commit()

    return attempts


def reset_failed_attempts(username: str) -> None:
    """reset failed attempts after a successful login"""
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET failed_attempts = 0
            WHERE username = ?
            """,
            (username,),
        )
        conn.commit()


def list_users() -> list[dict[str, Any]]:
    """return non-sensitive user information for admin ortesting display"""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT username, access_level, failed_attempts, locked
            FROM users
            ORDER BY username
            """
        ).fetchall()
    return [dict(row) for row in rows]
