"""Tenant export worker (Safe)."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

SECRET_KEY = b"secure_internal_signing_key"


def verify_tenant_authorization(tenant_id: str, auth_token: str) -> bool:
    """Verify cryptographic token for tenant access."""
    expected = hmac.new(SECRET_KEY, tenant_id.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, auth_token)


def load_tenant_confidential_records(tenant_id: str) -> list[dict[str, Any]]:
    return [{"tenant_id": tenant_id, "secret_key": "confidential_data"}]


def execute_export_transmission(recipient: str, records: list[dict[str, Any]]) -> bool:
    return True


def process_tenant_export_worker(job: dict[str, Any]) -> dict[str, Any]:
    """Process tenant export task.

    SAFE: Validates cryptographic auth_token before loading tenant records.
    """
    tenant_id = job["tenant_id"]
    recipient = job["recipient_email"]
    auth_token = job.get("auth_token", "")

    # Independent worker-side verification of tenant authority
    if not verify_tenant_authorization(tenant_id, auth_token):
        return {"status": "rejected", "error": "Invalid tenant authorization token"}

    records = load_tenant_confidential_records(tenant_id)
    execute_export_transmission(recipient, records)

    return {"status": "exported", "tenant_id": tenant_id, "count": len(records)}
