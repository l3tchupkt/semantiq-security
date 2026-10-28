"""Tenant database and organization membership lookup repository."""

from __future__ import annotations

from typing import Any

TENANTS_DB: dict[str, dict[str, Any]] = {
    "tenant_alpha": {
        "tenant_id": "tenant_alpha",
        "name": "Alpha Corp",
        "members": ["user_alpha_1", "user_alpha_2"],
        "tier": "enterprise",
    },
    "tenant_beta": {
        "tenant_id": "tenant_beta",
        "name": "Beta LLC",
        "members": ["user_beta_1"],
        "tier": "starter",
    },
}


def get_tenant_record(tenant_id: str) -> dict[str, Any] | None:
    """Retrieve tenant profile details by tenant ID."""
    return TENANTS_DB.get(tenant_id)


def verify_user_tenant_membership(user_id: str, tenant_id: str) -> bool:
    """Verify whether a user belongs to the specified tenant."""
    record = get_tenant_record(tenant_id)
    if not record:
        return False
    return user_id in record.get("members", [])

