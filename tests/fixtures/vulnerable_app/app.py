"""Intentionally vulnerable test fixture application for Semantiq evaluation."""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import tempfile

import requests
from db import execute_raw_query

try:
    from flask import make_response, redirect, render_template_string
except ImportError:
    def make_response(content: str) -> object:  # type: ignore
        return content

    def redirect(url: str) -> object:  # type: ignore
        return url

    def render_template_string(template: str) -> str:  # type: ignore
        return template

# VULNERABILITY: Hardcoded AWS Credential
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


def vulnerable_command_injection(user_input: str) -> None:
    # VULNERABILITY: Command Injection via shell=True
    cmd = f"ping -c 1 {user_input}"
    subprocess.run(cmd, shell=True)


def vulnerable_os_system(user_input: str) -> None:
    # VULNERABILITY: Command Injection via os.system
    os.system("echo " + user_input)


def vulnerable_sql_injection(cursor: sqlite3.Cursor, user_id: str) -> list:
    # VULNERABILITY: SQL Injection via f-string
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()


def vulnerable_path_traversal(filename: str) -> str:
    # VULNERABILITY: Path Traversal via open()
    filepath = f"uploads/{filename}"
    with open(filepath) as f:
        return f.read()


def vulnerable_ssrf(target_url: str) -> str:
    # VULNERABILITY: SSRF via requests.get()
    response = requests.get(target_url)
    return response.text


def vulnerable_deserialization(raw_payload: bytes) -> object:
    # VULNERABILITY: Unsafe Deserialization via pickle.loads
    return pickle.loads(raw_payload)


def vulnerable_crypto(password: str) -> str:
    # VULNERABILITY: Weak hash algorithm MD5
    hasher = hashlib.md5(password.encode())
    return hasher.hexdigest()


def vulnerable_file_permissions(filepath: str) -> None:
    # VULNERABILITY: Overly permissive file permissions 0o777
    os.chmod(filepath, 0o777)


def vulnerable_tempfile() -> str:
    # VULNERABILITY: Insecure tempfile creation
    return tempfile.mktemp()


def vulnerable_cross_file_query(cursor: sqlite3.Cursor, category_filter: str) -> list:
    # VULNERABILITY: Cross-file SQL Injection passing dynamic query into helper
    query = f"SELECT * FROM inventory WHERE cat = '{category_filter}'"
    return execute_raw_query(cursor, query)


def vulnerable_eval(user_formula: str) -> object:
    # VULNERABILITY: Code injection via eval
    return eval(user_formula)


def vulnerable_ssti(user_name: str) -> str:
    # VULNERABILITY: Server-Side Template Injection
    return render_template_string(f"Hello {user_name}!")


def vulnerable_xss(user_comment: str) -> object:
    # VULNERABILITY: Reflected XSS
    return make_response(f"<div>{user_comment}</div>")


def vulnerable_redirect(dest_url: str) -> object:
    # VULNERABILITY: Open URL Redirection
    return redirect(dest_url)

