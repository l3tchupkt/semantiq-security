"""User account profile service."""

import sqlite3


def get_user_profile(user_id: str) -> dict:
    """Retrieve and serialize user profile including plaintext credential fields.

    VULNERABILITY: SQ-PY-017 Sensitive Data Exposure (password_hash and api_key exposed)
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, api_key FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        return {}

    return {
        "user_id": row[0],
        "username": row[1],
        "password_hash": row[2],
        "api_key": row[3],
    }
