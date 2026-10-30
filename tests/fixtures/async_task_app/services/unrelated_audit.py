"""Unrelated audit event logging (Negative Case)."""
from __future__ import annotations

from typing import Any

# Declares an isolated queue that has NO producers in api/tasks.py
AUDIT_EVENT_QUEUE: list[dict[str, Any]] = []


def process_audit_worker(job: dict[str, Any]) -> dict[str, Any]:
    """Worker processing audit events.

    NEGATIVE CASE: This consumer handles audit events (audit_log_id, severity).
    It must NOT be connected to TENANT_JOBS_QUEUE or ADMIN_TASKS_QUEUE.
    """
    audit_id = job.get("audit_log_id")
    severity = job.get("severity")
    return {"status": "logged", "id": audit_id, "sev": severity}
