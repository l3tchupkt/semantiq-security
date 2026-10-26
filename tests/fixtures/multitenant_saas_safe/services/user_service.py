"""Safe user profile service excluding credentials from response."""

import sqlite3


def safe_get_user_profile(user_id: str) -> dict:
    """Safely return user profile excluding password_hash and secret tokens."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        return {}

    # Safe DTO excluding password and API keys
    return {
        "user_id": row[0],
        "username": row[1],
    }
