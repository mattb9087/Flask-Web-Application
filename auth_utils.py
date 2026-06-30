"""Authentication helper functions for the secure intranet"""

import hashlib
import os
import re
import secrets
import string

SALT_LENGTH = 40
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 25

SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:,.?/"


def hash_password(plain_text: str) -> str:
    """return a stored salted SHA-1 password value as salt + hash. The stored
    value is 80 characters total: first 40 from salt and last 40 are the SHA-1 hash.
    """
    salt = os.urandom(20).hex()
    hashable = (salt + plain_text).encode("utf-8")
    password_hash = hashlib.sha1(hashable).hexdigest()
    return salt + password_hash


def verify_password(stored_value: str, plain_text: str) -> bool:
    """verify a plaintext password against the stored salt + SHA-1 hash"""
    if not stored_value or len(stored_value) <= SALT_LENGTH:
        return False

    salt = stored_value[:SALT_LENGTH]
    stored_hash = stored_value[SALT_LENGTH:]
    hashable = (salt + plain_text).encode("utf-8")
    candidate_hash = hashlib.sha1(hashable).hexdigest()
    return secrets.compare_digest(candidate_hash, stored_hash)


def validate_password(password: str) -> tuple[bool, str]:
    """validate password complexity requirements from the assignmentv"""
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, "Password must be at least 8 characters long."
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, "Password must be at most 25 characters long."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."


def generate_strong_password(length: int = 14) -> str:
    """generate a strong password that satisfies the validation rules"""
    if length < PASSWORD_MIN_LENGTH or length > PASSWORD_MAX_LENGTH:
        length = 14

    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(SPECIAL_CHARACTERS),
    ]
    all_chars = string.ascii_letters + string.digits + SPECIAL_CHARACTERS
    remaining = [secrets.choice(all_chars) for _ in range(length - len(required))]
    password_chars = required + remaining
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
