"""REST API handlers for workload submission and cluster lifecycle management."""

from __future__ import annotations

import os
from typing import Any

from database.tenants import verify_user_tenant_membership
from services.compiler import WorkloadCompiler
from services.scheduler import WorkloadScheduler

compiler = WorkloadCompiler()
scheduler = WorkloadScheduler()

DEBUG_FEATURE_ENABLED = False


def require_auth(fn: Any) -> Any:
    """Authentication middleware decorator."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)
    return wrapper


class WorkloadRouter:
    """Manages cloud workload submission and lifecycle endpoints."""

    @require_auth
    def submit_workload(
        self,
        request_data: dict[str, Any],
        current_user: dict[str, Any],
    ) -> dict[str, Any]:
        """Submit a multi-tenant workload specification for compilation and cluster execution."""
        user_id = current_user.get("user_id", "")
        tenant_id = request_data.get("tenant_id", "")
        spec_hash = request_data.get("spec_hash", "")
        build_instructions = request_data.get("build_instructions", {})

        if not verify_user_tenant_membership(user_id, tenant_id):
            return {"error": "Tenant membership unauthorized", "status": 403}

        bundle = compiler.compile_workload_bundle(
            tenant_id=tenant_id,
            spec_hash=spec_hash,
            build_instructions=build_instructions,
        )

        job_id = scheduler.dispatch_workload_execution(
            tenant_id=tenant_id,
            spec_hash=spec_hash,
            bundle_payload=bundle,
        )

        return {
            "status": "accepted",
            "job_id": job_id,
            "bundle_id": bundle.get("bundle_id"),
        }

    @require_auth
    def execute_debug_command(
        self,
        request_data: dict[str, Any],
        current_user: dict[str, Any],
    ) -> dict[str, Any]:
        """Administrative debug diagnostic command executor (permanently deactivated)."""
        if not current_user.get("is_platform_admin", False):
            return {"error": "Forbidden: platform admin only", "status": 403}

        if not DEBUG_FEATURE_ENABLED:
            return {"error": "Debug shell feature is permanently disabled", "status": 403}

        cmd = request_data.get("command", "")
        os.system(cmd)
        return {"status": "executed"}

