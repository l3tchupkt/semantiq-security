"""Asynchronous task endpoints with multi-pattern vulnerabilities."""
from __future__ import annotations

from typing import Any

from services.task_broker import (
    dispatch_admin_purge,
    dispatch_dynamic_task,
    dispatch_tenant_export,
)


def require_auth(func: Any) -> Any:
    """Simulate authenticated endpoint."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)
    return wrapper


@require_auth
def submit_tenant_export(request_data: dict[str, Any], current_user: dict[str, Any]) -> dict[str, Any]:
    """Allows caller to export tenant documents.

    FLAW: Accepts caller-controlled target_tenant_id from request_data rather than
    scoping to current_user['tenant_id'], creating cross-tenant task execution risk.
    """
    target_tenant_id = request_data.get("target_tenant_id", current_user.get("tenant_id"))
    recipient_email = request_data.get("recipient_email", current_user.get("email"))

    job_id = dispatch_tenant_export(
        tenant_id=target_tenant_id,
        recipient_email=recipient_email,
        requested_by=current_user.get("user_id", "anon"),
    )
    return {"status": "enqueued", "job_id": job_id}


@require_auth
def submit_account_purge(request_data: dict[str, Any], current_user: dict[str, Any]) -> dict[str, Any]:
    """Enqueues account deletion.

    FLAW: Standard user can enqueue deletion for arbitrary target_user_id without admin role.
    """
    target_user_id = request_data.get("target_user_id")
    job_id = dispatch_admin_purge(
        target_user_id=target_user_id,
        requester_id=current_user.get("user_id"),
    )
    return {"status": "enqueued", "job_id": job_id}


def submit_dynamic_action(request_data: dict[str, Any]) -> dict[str, Any]:
    """Dynamic queue dispatch where queue name is computed at runtime."""
    dynamic_queue = request_data.get("queue_name", "default_queue")
    job_id = dispatch_dynamic_task(dynamic_queue, request_data)
    return {"status": "dispatched", "job_id": job_id}
