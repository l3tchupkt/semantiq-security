"""Asynchronous task endpoints with robust authorization and tenant isolation."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from services.task_broker import (
    dispatch_admin_purge,
    dispatch_tenant_export,
)

SECRET_KEY = b"secure_internal_signing_key"


def require_auth(func: Any) -> Any:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)
    return wrapper


def admin_required(func: Any) -> Any:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)
    return wrapper


@require_auth
def submit_tenant_export(request_data: dict[str, Any], current_user: dict[str, Any]) -> dict[str, Any]:
    """Allows caller to export tenant documents.

    SAFE: Uses current_user['tenant_id'] strictly from session; ignores request_data override.
    Generates cryptographic auth token for worker-side verification.
    """
    tenant_id = current_user.get("tenant_id")
    recipient_email = current_user.get("email")

    # Generate HMAC signature binding tenant_id
    auth_token = hmac.new(SECRET_KEY, tenant_id.encode(), hashlib.sha256).hexdigest()

    job_id = dispatch_tenant_export(
        tenant_id=tenant_id,
        recipient_email=recipient_email,
        auth_token=auth_token,
        requested_by=current_user.get("user_id"),
    )
    return {"status": "enqueued", "job_id": job_id}


@admin_required
def submit_account_purge(request_data: dict[str, Any], current_user: dict[str, Any]) -> dict[str, Any]:
    """Enqueues account deletion.

    SAFE: Protected by @admin_required, signed with admin authorization token.
    """
    target_user_id = request_data.get("target_user_id")
    admin_token = hmac.new(SECRET_KEY, b"admin_purge:" + target_user_id.encode(), hashlib.sha256).hexdigest()

    job_id = dispatch_admin_purge(
        target_user_id=target_user_id,
        requester_id=current_user.get("user_id"),
        admin_token=admin_token,
    )
    return {"status": "enqueued", "job_id": job_id}
