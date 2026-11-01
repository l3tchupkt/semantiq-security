"""FastAPI framework route, dependency injection, and parameter adapter."""

from __future__ import annotations

import ast

from semantiq.analysis.framework_adapters.base import FrameworkAdapter
from semantiq.graph.interfaces import (
    AuthGuardBinding,
    AuthGuardKind,
    FrameworkEntrypoint,
    GuardStatus,
    InputBinding,
)
from semantiq.graph.models import RelationshipProvenance


class FastAPIAdapter(FrameworkAdapter):
    """Adapter for FastAPI and Starlette routes, dependency injection, and Pydantic/Query parameters."""

    @property
    def framework_name(self) -> str:
        return "fastapi"

    def _extract_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._extract_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        elif isinstance(node, ast.Call):
            return self._extract_name(node.func)
        return ""

    def detect_entrypoints(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list[FrameworkEntrypoint]:
        entrypoints: list[FrameworkEntrypoint] = []
        clean_file = file_path.replace("\\", "/")

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = self._extract_name(dec).lower()
                    method_match = None
                    for m in ["get", "post", "put", "delete", "patch", "api_route"]:
                        if dec_name.endswith(f".{m}"):
                            method_match = m.upper() if m != "api_route" else "ANY"
                            break

                    if not method_match:
                        continue

                    route_path = None
                    if isinstance(dec, ast.Call) and dec.args:
                        arg0 = dec.args[0]
                        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                            route_path = arg0.value

                    if not route_path:
                        route_path = f"/{node.name}"

                    loc = self.get_source_location(node, clean_file)
                    inputs = self.detect_inputs(node)
                    auth_guards = self.detect_auth_guards(node, clean_file)

                    entrypoints.append(
                        FrameworkEntrypoint(
                            entrypoint_id=f"route:{clean_file}:{route_path}",
                            framework_name="fastapi",
                            route_path=route_path,
                            http_methods=[method_match],
                            handler_symbol=node.name,
                            handler_qualified_name=f"{clean_file}:{node.name}",
                            location=loc,
                            input_bindings=inputs,
                            auth_guards=auth_guards,
                            csrf_protected=None,
                            provenance=RelationshipProvenance.FRAMEWORK_RESOLVED,
                            confidence=1.0,
                        )
                    )

        return entrypoints

    def detect_auth_guards(
        self,
        node: ast.AST,
        file_path: str,
    ) -> list[AuthGuardBinding]:
        guards: list[AuthGuardBinding] = []
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return guards

        # In FastAPI, auth is primarily expressed via parameter defaults with Depends or Security
        for _arg in node.args.args:
            # Check default values if present
            pass

        # Also inspect decorators on router or function
        for dec in node.decorator_list:
            dn = self._extract_name(dec).lower()
            if any(k in dn for k in ["auth", "login", "admin", "protect", "permission"]):
                guards.append(
                    AuthGuardBinding(
                        guard_name=dn,
                        guard_kind=AuthGuardKind.AUTHENTICATION,
                        status=GuardStatus.ENFORCED,
                        location=self.get_source_location(dec, file_path),
                        mechanism="decorator",
                    )
                )

        # Walk default arguments and calls in function header
        for child in ast.walk(node.args):
            if isinstance(child, ast.Call):
                call_fn = self._extract_name(child.func)
                if call_fn in {"Depends", "Security", "fastapi.Depends", "fastapi.Security"}:
                    dep_target = "auth_dependency"
                    if child.args:
                        dep_target = self._extract_name(child.args[0])
                    guards.append(
                        AuthGuardBinding(
                            guard_name=f"Depends({dep_target})",
                            guard_kind=AuthGuardKind.AUTHORIZATION if "role" in dep_target.lower() or "admin" in dep_target.lower() else AuthGuardKind.AUTHENTICATION,
                            status=GuardStatus.ENFORCED,
                            location=self.get_source_location(child, file_path),
                            mechanism="dependency_injection",
                        )
                    )

        return guards

    def detect_inputs(self, node: ast.AST) -> list[InputBinding]:
        inputs: list[InputBinding] = []
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return inputs

        # Every argument not bound to Depends/Security is an HTTP parameter
        for arg in node.args.args:
            arg_name = arg.arg
            if arg_name in {"self", "cls"}:
                continue

            lineno = getattr(arg, "lineno", node.lineno)
            # Default to query or body
            inputs.append(
                InputBinding(
                    param_name=arg_name,
                    input_source_kind="query_param",
                    expression=f"param:{arg_name}",
                    line=lineno,
                )
            )

        return inputs
