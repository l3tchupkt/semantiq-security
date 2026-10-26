"""Safe file export retrieval with ownership validation and path resolution."""

import os

from flask import send_file

session = {"user_id": "usr_42"}


def safe_export_file(file_name: str) -> object:
    """Validate resource ownership and path canonicalization before file retrieval."""
    clean_name = os.path.basename(file_name)
    current_user = session.get("user_id")

    # Verify ownership invariant
    if not clean_name.startswith(f"{current_user}_"):
        raise PermissionError("Access denied to requested file export")

    return send_file(f"exports/{clean_name}")
