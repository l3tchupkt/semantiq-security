"""Intentionally secure fixture application."""

import hashlib
import os
import sqlite3
import subprocess
import tempfile


def safe_command(dest: str) -> None:
    # SAFE: Argument array without shell=True
    subprocess.run(["ping", "-c", "1", dest], shell=False, check=True)


def safe_sql(cursor: sqlite3.Cursor, user_id: str) -> list:
    # SAFE: Parameterized query placeholder
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def safe_crypto(password: str) -> str:
    # SAFE: SHA-256
    return hashlib.sha256(password.encode()).hexdigest()


def safe_permissions(filepath: str) -> None:
    # SAFE: Restrictive 0o600
    os.chmod(filepath, 0o600)


def safe_tempfile() -> str:
    # SAFE: NamedTemporaryFile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        return f.name
