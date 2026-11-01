"""Registry coordinating framework adapters for multi-framework entrypoint analysis."""

from __future__ import annotations

import ast

from semantiq.analysis.framework_adapters.base import FrameworkAdapter
from semantiq.analysis.framework_adapters.bottle_adapter import BottleAdapter
from semantiq.analysis.framework_adapters.django_adapter import DjangoAdapter
from semantiq.analysis.framework_adapters.fastapi_adapter import FastAPIAdapter
from semantiq.analysis.framework_adapters.flask_adapter import FlaskAdapter
from semantiq.analysis.framework_adapters.tornado_adapter import TornadoAdapter
from semantiq.graph.interfaces import (
    AuthGuardBinding,
    FrameworkEntrypoint,
    InputBinding,
)


class FrameworkAdapterRegistry:
    """Coordinates framework adapters in priority order: Bottle, Flask, FastAPI, Django, Tornado."""

    def __init__(self) -> None:
        self.adapters: list[FrameworkAdapter] = [
            BottleAdapter(),
            FlaskAdapter(),
            FastAPIAdapter(),
            DjangoAdapter(),
            TornadoAdapter(),
        ]

    def register_adapter(self, adapter: FrameworkAdapter) -> None:
        self.adapters.insert(0, adapter)

    def detect_all_entrypoints(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list[FrameworkEntrypoint]:
        entrypoints: list[FrameworkEntrypoint] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for adapter in self.adapters:
            detected = adapter.detect_entrypoints(tree, file_path, source_lines)
            for ep in detected:
                key = (ep.location.file_path, ep.route_path, ep.handler_symbol)
                if key not in seen_keys:
                    seen_keys.add(key)
                    entrypoints.append(ep)
        return entrypoints

    def detect_auth_guards(
        self,
        node: ast.AST,
        file_path: str,
    ) -> list[AuthGuardBinding]:
        guards: list[AuthGuardBinding] = []
        for adapter in self.adapters:
            detected = adapter.detect_auth_guards(node, file_path)
            guards.extend(detected)
        return guards

    def detect_inputs(
        self,
        node: ast.AST,
    ) -> list[InputBinding]:
        inputs: list[InputBinding] = []
        for adapter in self.adapters:
            detected = adapter.detect_inputs(node)
            inputs.extend(detected)
        return inputs


GLOBAL_FRAMEWORK_ADAPTER_REGISTRY = FrameworkAdapterRegistry()
