"""Safe role assignment with admin privilege verification."""

import sqlite3

session = {"user_role": "admin"}


def safe_assign_role(user_id: str, new_role: str) -> str:
    """Assign role only after checking caller's administrative permission."""
    if session.get("user_role") != "admin":
        raise PermissionError("Admin required")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    return "role_assigned"
