"""Unrelated audit event logging (Negative Case)."""
from __future__ import annotations

from typing import Any

AUDIT_EVENT_QUEUE: list[dict[str, Any]] = []


def process_audit_worker(job: dict[str, Any]) -> dict[str, Any]:
    """Worker processing audit events."""
    audit_id = job.get("audit_log_id")
    severity = job.get("severity")
    return {"status": "logged", "id": audit_id, "sev": severity}
