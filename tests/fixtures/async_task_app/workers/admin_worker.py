"""Privileged admin task worker."""
from __future__ import annotations

from typing import Any


def execute_database_purge(user_id: str) -> bool:
    """Execute destructive deletion in database."""
    return True


def process_admin_purge_worker(job: dict[str, Any]) -> dict[str, Any]:
    """Process administrative purge task.

    VULNERABILITY: Missing worker-side authorization check.
    Executes destructive purge without verifying requester_id is an administrator.
    """
    target_user_id = job["target_user_id"]
    requester_id = job["requester_id"]

    # Destructive operation executed without re-authorizing requester
    execute_database_purge(target_user_id)

    return {"status": "purged", "target_user_id": target_user_id, "by": requester_id}
