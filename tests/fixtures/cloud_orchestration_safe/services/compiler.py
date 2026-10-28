"""Workload bundle compilation and packaging service."""

from __future__ import annotations

import hashlib
from typing import Any

from services.cache import BundleCache

cache = BundleCache()


class WorkloadCompiler:
    """Compiles workload specifications and container templates into execution bundles."""

    def compile_workload_bundle(
        self,
        tenant_id: str,
        spec_hash: str,
        build_instructions: dict[str, Any],
    ) -> dict[str, Any]:
        """Compile or retrieve existing cached workload execution bundle with tenant isolation.

        Parameters:
            tenant_id: organization submitting workload
            spec_hash: content addressable hash of the workload definition
            build_instructions: execution command, environment variables, and image
        """
        cache_key = f"bundle:{tenant_id}:{spec_hash}"
        cached = cache.get_bundle(cache_key)
        if cached is not None:
            return cached

        bundle_id = hashlib.sha256(f"{tenant_id}:{spec_hash}".encode()).hexdigest()[:16]
        bundle = {
            "bundle_id": bundle_id,
            "origin_tenant": tenant_id,
            "spec_hash": spec_hash,
            "entrypoint": build_instructions.get("entrypoint", "python -m main"),
            "environment": build_instructions.get("env", {}),
            "status": "COMPILED",
        }
        cache.store_bundle(cache_key, bundle)
        return bundle

