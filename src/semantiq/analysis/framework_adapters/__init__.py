"""Framework adapters for web routes, inputs, and security boundaries."""

from __future__ import annotations

from semantiq.analysis.framework_adapters.base import FrameworkAdapter
from semantiq.analysis.framework_adapters.bottle_adapter import BottleAdapter
from semantiq.analysis.framework_adapters.django_adapter import DjangoAdapter
from semantiq.analysis.framework_adapters.fastapi_adapter import FastAPIAdapter
from semantiq.analysis.framework_adapters.flask_adapter import FlaskAdapter
from semantiq.analysis.framework_adapters.registry import (
    GLOBAL_FRAMEWORK_ADAPTER_REGISTRY,
    FrameworkAdapterRegistry,
)
from semantiq.analysis.framework_adapters.tornado_adapter import TornadoAdapter

__all__ = [
    "FrameworkAdapter",
    "BottleAdapter",
    "FlaskAdapter",
    "FastAPIAdapter",
    "DjangoAdapter",
    "TornadoAdapter",
    "FrameworkAdapterRegistry",
    "GLOBAL_FRAMEWORK_ADAPTER_REGISTRY",
]

