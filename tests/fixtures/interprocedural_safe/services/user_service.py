"""Safe user management service."""

import sqlite3


def delete_user_account(user_id: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"status": "deleted", "user_id": user_id}
