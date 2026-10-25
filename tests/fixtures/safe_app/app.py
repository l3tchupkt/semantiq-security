"""Intentionally secure fixture application."""

import hashlib
import os
import sqlite3
import subprocess
import tempfile

from db import execute_safe_query

try:
    from flask import make_response, redirect
except ImportError:
    def make_response(content: str) -> object:  # type: ignore
        return content

    def redirect(url: str) -> object:  # type: ignore
        return url


def safe_command(dest: str) -> None:
    # SAFE: Argument array without shell=True
    subprocess.run(["ping", "-c", "1", dest], shell=False, check=True)


def safe_sql(cursor: sqlite3.Cursor, user_id: str) -> list:
    # SAFE: Parameterized query placeholder
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def safe_alias_query(cursor: sqlite3.Cursor) -> list:
    # SAFE: Aliased constant string literal
    static_sql = "SELECT id, username FROM users ORDER BY id ASC"
    aliased_sql = static_sql
    cursor.execute(aliased_sql)
    return cursor.fetchall()


def safe_cross_file(cursor: sqlite3.Cursor, user_id: str) -> list:
    # SAFE: Cross-file helper using parameterized placeholders
    return execute_safe_query(cursor, "SELECT * FROM items WHERE id = ?", (user_id,))


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


def safe_xss(user_comment: str) -> object:
    # SAFE: html.escape applied before response rendering
    import html

    escaped = html.escape(user_comment)
    return make_response(f"<div>{escaped}</div>")


def safe_redirect() -> object:
    # SAFE: Static internal redirect target
    return redirect("/dashboard")


class App:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator

app = App()

def login_required(f):
    return f

def admin_required(f):
    return f


@app.route("/api/documents/<doc_id>")
@login_required
def safe_idor_document(doc_id: str) -> list:
    # SAFE: Scoped by session user ID
    session_uid = "user_123"
    cursor = sqlite3.connect("app.db").cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ? AND owner_id = ?", (doc_id, session_uid))
    return cursor.fetchall()


@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
@admin_required
def safe_admin_delete(user_id: str) -> str:
    # SAFE: Protected by admin_required decorator
    cursor = sqlite3.connect("app.db").cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "deleted"
