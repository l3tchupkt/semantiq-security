"""Central task queues and dispatchers."""
from __future__ import annotations

import uuid
from typing import Any

TENANT_JOBS_QUEUE: list[dict[str, Any]] = []
ADMIN_TASKS_QUEUE: list[dict[str, Any]] = []
ANALYTICS_QUEUE: list[dict[str, Any]] = []


def dispatch_tenant_export(tenant_id: str, recipient_email: str, requested_by: str) -> str:
    """Enqueue tenant export job."""
    job_id = f"job_ten_{uuid.uuid4().hex[:8]}"
    payload = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "recipient_email": recipient_email,
        "requested_by": requested_by,
    }
    TENANT_JOBS_QUEUE.append(payload)
    return job_id


def dispatch_admin_purge(target_user_id: str, requester_id: str) -> str:
    """Enqueue account deletion task."""
    job_id = f"job_adm_{uuid.uuid4().hex[:8]}"
    payload = {
        "job_id": job_id,
        "target_user_id": target_user_id,
        "requester_id": requester_id,
    }
    ADMIN_TASKS_QUEUE.append(payload)
    return job_id


def dispatch_dynamic_task(queue_target: Any, payload: dict[str, Any]) -> str:
    """Dynamic dispatch without static target."""
    job_id = f"job_dyn_{uuid.uuid4().hex[:8]}"
    if hasattr(queue_target, "append"):
        queue_target.append({"job_id": job_id, "data": payload})
    return job_id
