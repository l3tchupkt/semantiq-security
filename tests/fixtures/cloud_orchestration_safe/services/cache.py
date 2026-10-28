"""Workload artifact and compiled bundle cache service."""

from __future__ import annotations

from typing import Any

GLOBAL_BUNDLE_CACHE: dict[str, dict[str, Any]] = {}


class BundleCache:
    """In-memory cache for compiled workload binaries and execution bundles."""

    def __init__(self) -> None:
        self._store = GLOBAL_BUNDLE_CACHE

    def get_bundle(self, key: str) -> dict[str, Any] | None:
        return self._store.get(key)

    def store_bundle(self, key: str, payload: dict[str, Any]) -> None:
        self._store[key] = payload

