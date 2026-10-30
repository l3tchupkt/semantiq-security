"""Privileged admin task worker (Safe)."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

SECRET_KEY = b"secure_internal_signing_key"


def verify_admin_token(target_user_id: str, admin_token: str) -> bool:
    """Verify cryptographic token for administrative purge."""
    expected = hmac.new(SECRET_KEY, b"admin_purge:" + target_user_id.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, admin_token)


def execute_database_purge(user_id: str) -> bool:
    return True


def process_admin_purge_worker(job: dict[str, Any]) -> dict[str, Any]:
    """Process administrative purge task.

    SAFE: Worker verifies cryptographic admin_token before destructive deletion.
    """
    target_user_id = job["target_user_id"]
    admin_token = job.get("admin_token", "")

    # Independent worker-side authorization check
    if not verify_admin_token(target_user_id, admin_token):
        return {"status": "rejected", "error": "Unauthorized administrative operation"}

    execute_database_purge(target_user_id)
    return {"status": "purged", "target_user_id": target_user_id}
