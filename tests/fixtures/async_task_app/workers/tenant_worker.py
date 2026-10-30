"""Tenant export worker."""
from __future__ import annotations

from typing import Any


def load_tenant_confidential_records(tenant_id: str) -> list[dict[str, Any]]:
    """Simulate loading confidential tenant data from storage."""
    return [{"tenant_id": tenant_id, "secret_key": "confidential_data"}]


def execute_export_transmission(recipient: str, records: list[dict[str, Any]]) -> bool:
    """Send exported records to external email/sink."""
    return True


def process_tenant_export_worker(job: dict[str, Any]) -> dict[str, Any]:
    """Process tenant export task.

    VULNERABILITY: Blindly trusts job['tenant_id'] without verifying caller ownership.
    """
    tenant_id = job["tenant_id"]
    recipient = job["recipient_email"]

    records = load_tenant_confidential_records(tenant_id)
    execute_export_transmission(recipient, records)

    return {"status": "exported", "tenant_id": tenant_id, "count": len(records)}
