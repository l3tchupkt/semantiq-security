"""Administrative role assignment service."""

import sqlite3


def assign_role(user_id: str, new_role: str) -> str:
    """Assign administrative role to a target user without caller role verification.

    VULNERABILITY: SQ-PY-014 Missing Function-Level Authorization / Privilege Escalation
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Privileged role modification without admin authorization check
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    return "role_assigned"
