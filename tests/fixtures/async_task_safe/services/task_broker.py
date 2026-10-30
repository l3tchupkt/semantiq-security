"""Central task queues and dispatchers (Safe)."""
from __future__ import annotations

import uuid
from typing import Any

TENANT_JOBS_QUEUE: list[dict[str, Any]] = []
ADMIN_TASKS_QUEUE: list[dict[str, Any]] = []


def dispatch_tenant_export(tenant_id: str, recipient_email: str, auth_token: str, requested_by: str) -> str:
    """Enqueue tenant export job with cryptographic auth token."""
    job_id = f"job_ten_{uuid.uuid4().hex[:8]}"
    payload = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "recipient_email": recipient_email,
        "auth_token": auth_token,
        "requested_by": requested_by,
    }
    TENANT_JOBS_QUEUE.append(payload)
    return job_id


def dispatch_admin_purge(target_user_id: str, requester_id: str, admin_token: str) -> str:
    """Enqueue account deletion task with admin authorization token."""
    job_id = f"job_adm_{uuid.uuid4().hex[:8]}"
    payload = {
        "job_id": job_id,
        "target_user_id": target_user_id,
        "requester_id": requester_id,
        "admin_token": admin_token,
    }
    ADMIN_TASKS_QUEUE.append(payload)
    return job_id
