"""Bottle framework route, input, and guard adapter."""

from __future__ import annotations

import ast
import contextlib

from semantiq.analysis.framework_adapters.base import FrameworkAdapter
from semantiq.graph.interfaces import (
    AuthGuardBinding,
    AuthGuardKind,
    FrameworkEntrypoint,
    GuardStatus,
    InputBinding,
)
from semantiq.graph.models import RelationshipProvenance


class BottleAdapter(FrameworkAdapter):
    """Adapter for Bottle web framework routing, request parameters, and static handlers."""

    @property
    def framework_name(self) -> str:
        return "bottle"

    def _extract_decorator_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._extract_decorator_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        elif isinstance(node, ast.Call):
            return self._extract_decorator_name(node.func)
        return ""

    def _extract_route_methods_and_path(
        self, call_node: ast.Call, dec_name: str
    ) -> tuple[str | None, list[str]]:
        route_path: str | None = None
        methods: list[str] = []

        # Infer method from decorator name: e.g. bottle.get -> GET
        dec_clean = dec_name.lower().split(".")[-1]
        if dec_clean in {"get", "post", "put", "delete", "patch"}:
            methods = [dec_clean.upper()]

        # Extract path from first argument
        if call_node.args:
            first_arg = call_node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                route_path = first_arg.value

        # Check keyword args: e.g. method='POST' or method=['GET', 'POST']
        for kw in call_node.keywords:
            if kw.arg == "method":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    methods = [kw.value.value.upper()]
                elif isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    extracted = []
                    for el in kw.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            extracted.append(el.value.upper())
                    if extracted:
                        methods = extracted

        if not methods:
            methods = ["GET"]

        return route_path, methods

    def detect_entrypoints(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list[FrameworkEntrypoint]:
        entrypoints: list[FrameworkEntrypoint] = []
        clean_file = file_path.replace("\\", "/")

        has_bottle_import = any(
            isinstance(n, (ast.Import, ast.ImportFrom))
            and (
                any("bottle" in getattr(alias, "name", "") for alias in getattr(n, "names", []))
                or (isinstance(n, ast.ImportFrom) and n.module and "bottle" in n.module)
            )
            for n in getattr(tree, "body", [])
        )

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = self._extract_decorator_name(dec)
                    # Bottle routes: @bottle.route, @route, @bottle.get, etc.
                    # If bottle is explicitly imported, also recognize @app.route, @App.route
                    if has_bottle_import:
                        is_bottle_route = any(
                            dec_name == pattern
                            or dec_name.endswith(f".{pattern}")
                            for pattern in ["route", "get", "post", "put", "delete", "patch"]
                        ) and not any(dec_name.startswith(p) for p in ["bp.", "blueprint."])
                    else:
                        is_flask_or_fastapi = any(
                            dec_name.startswith(p)
                            for p in ["bp.", "blueprint.", "app.", "router.", "api_router."]
                        )
                        is_bottle_route = not is_flask_or_fastapi and (
                            dec_name in {"route", "get", "post", "put", "delete", "patch"}
                            or dec_name.startswith("bottle.")
                            or "bottle" in dec_name.lower()
                        )

                    if not is_bottle_route:
                        continue

                    route_path = None
                    methods = ["GET"]
                    if isinstance(dec, ast.Call):
                        route_path, methods = self._extract_route_methods_and_path(dec, dec_name)

                    if not route_path:
                        route_path = f"/{node.name}"

                    loc = self.get_source_location(node, clean_file)
                    inputs = self.detect_inputs(node)
                    auth_guards = self.detect_auth_guards(node, clean_file)

                    entrypoints.append(
                        FrameworkEntrypoint(
                            entrypoint_id=f"route:{clean_file}:{route_path}",
                            framework_name="bottle",
                            route_path=route_path,
                            http_methods=methods,
                            handler_symbol=node.name,
                            handler_qualified_name=f"{clean_file}:{node.name}",
                            location=loc,
                            input_bindings=inputs,
                            auth_guards=auth_guards,
                            csrf_protected=None,  # Bottle has no default CSRF protection
                            provenance=RelationshipProvenance.FRAMEWORK_RESOLVED,
                            confidence=1.0,
                        )
                    )

        # Check imperative route calls at module level: bottle.route('/...', callback=fn)
        if hasattr(tree, "body"):
            for stmt in tree.body:
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    call_name = self._extract_decorator_name(stmt.value.func)
                    if call_name in {"bottle.route", "app.route", "default_app().route"} and stmt.value.args:
                        route_path = None
                        if isinstance(stmt.value.args[0], ast.Constant) and isinstance(stmt.value.args[0].value, str):
                            route_path = stmt.value.args[0].value

                        handler_name = "<callback>"
                        for kw in stmt.value.keywords:
                            if kw.arg == "callback" and isinstance(kw.value, ast.Name):
                                handler_name = kw.value.id

                        if route_path:
                            loc = self.get_source_location(stmt.value, clean_file)
                            entrypoints.append(
                                FrameworkEntrypoint(
                                    entrypoint_id=f"route:{clean_file}:{route_path}",
                                    framework_name="bottle",
                                    route_path=route_path,
                                    http_methods=["GET"],
                                    handler_symbol=handler_name,
                                    handler_qualified_name=f"{clean_file}:{handler_name}",
                                    location=loc,
                                    input_bindings=[],
                                    auth_guards=[],
                                    csrf_protected=False,
                                    provenance=RelationshipProvenance.FRAMEWORK_RESOLVED,
                                    confidence=0.9,
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

        for dec in node.decorator_list:
            dec_name = self._extract_decorator_name(dec).lower()
            if any(k in dec_name for k in ["auth", "login", "admin", "protect", "role"]):
                guard_kind = AuthGuardKind.AUTHORIZATION if any(k in dec_name for k in ["admin", "role"]) else AuthGuardKind.AUTHENTICATION
                guards.append(
                    AuthGuardBinding(
                        guard_name=dec_name,
                        guard_kind=guard_kind,
                        status=GuardStatus.ENFORCED,
                        location=self.get_source_location(dec, file_path),
                        mechanism="decorator",
                    )
                )

        # Check for imperative auth checks inside the body
        for child in ast.walk(node):
            if isinstance(child, ast.If):
                test_str = ""
                if hasattr(ast, "unparse"):
                    with contextlib.suppress(Exception):
                        test_str = ast.unparse(child.test).lower()
                if any(k in test_str for k in ["is_authenticated", "logged_in", "current_user", "has_permission"]):
                    guards.append(
                        AuthGuardBinding(
                            guard_name="imperative_auth_check",
                            guard_kind=AuthGuardKind.AUTHENTICATION,
                            status=GuardStatus.ENFORCED,
                            location=self.get_source_location(child, file_path),
                            mechanism="imperative_check",
                        )
                    )

        return guards

    def detect_inputs(self, node: ast.AST) -> list[InputBinding]:
        inputs: list[InputBinding] = []

        for child in ast.walk(node):
            lineno = getattr(child, "lineno", 1)

            if isinstance(child, ast.Attribute):
                val_name = ""
                if isinstance(child.value, ast.Name):
                    val_name = child.value.id
                elif isinstance(child.value, ast.Attribute) and isinstance(child.value.value, ast.Name):
                    val_name = f"{child.value.value.id}.{child.value.attr}"

                attr = child.attr.lower()
                full_attr = f"{val_name}.{attr}".lower() if val_name else attr

                if "request." in full_attr or full_attr.startswith("request."):
                    kind = "query_param"
                    if attr in {"forms", "post", "json", "body"}:
                        kind = "body"
                    elif attr in {"headers"}:
                        kind = "header"
                    elif attr in {"cookies"}:
                        kind = "cookie"
                    elif attr in {"files"}:
                        kind = "file"

                    inputs.append(
                        InputBinding(
                            param_name=attr,
                            input_source_kind=kind,
                            expression=full_attr,
                            line=lineno,
                        )
                    )

            elif isinstance(child, ast.Call):
                func_name = self._extract_decorator_name(child.func).lower()
                if "request." in func_name and any(k in func_name for k in [".get.get", ".post.get", ".forms.get", ".query.get", ".params.get"]):
                    arg_name = "input"
                    if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, str):
                        arg_name = child.args[0].value
                    inputs.append(
                        InputBinding(
                            param_name=arg_name,
                            input_source_kind="body" if "form" in func_name or "post" in func_name else "query_param",
                            expression=func_name,
                            line=lineno,
                        )
                    )

        return inputs
