"""Document and file export retrieval service."""

from flask import send_file


def export_file(file_name: str) -> object:
    """Export and send file directly by filename without user ownership check.

    VULNERABILITY: SQ-PY-016 Insecure Direct File Access
    """
    target_path = f"exports/{file_name}"
    return send_file(target_path)
