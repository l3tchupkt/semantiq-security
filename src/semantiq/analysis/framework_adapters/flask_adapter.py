"""Flask framework route, request input, and guard adapter."""

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


class FlaskAdapter(FrameworkAdapter):
    """Adapter for Flask routes, Blueprints, request globals, and auth decorators."""

    @property
    def framework_name(self) -> str:
        return "flask"

    def _extract_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._extract_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        elif isinstance(node, ast.Call):
            return self._extract_name(node.func)
        return ""

    def _extract_route_methods_and_path(
        self, call_node: ast.Call, dec_name: str
    ) -> tuple[str | None, list[str]]:
        route_path: str | None = None
        methods: list[str] = []

        dec_lower = dec_name.lower().split(".")[-1]
        if dec_lower in {"get", "post", "put", "delete", "patch"}:
            methods = [dec_lower.upper()]

        if call_node.args:
            first_arg = call_node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                route_path = first_arg.value

        for kw in call_node.keywords:
            if kw.arg in {"methods", "method"}:
                if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    extracted = []
                    for el in kw.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            extracted.append(el.value.upper())
                    if extracted:
                        methods = extracted
                elif isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    methods = [kw.value.value.upper()]

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
        has_flask_import = any(
            isinstance(n, (ast.Import, ast.ImportFrom))
            and (
                any("flask" in getattr(alias, "name", "") for alias in getattr(n, "names", []))
                or (isinstance(n, ast.ImportFrom) and n.module and "flask" in n.module)
            )
            for n in getattr(tree, "body", [])
        )
        # If the file imports bottle and does not import flask, leave route detection to BottleAdapter
        if has_bottle_import and not has_flask_import:
            return []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = self._extract_name(dec)
                    dec_clean = dec_name.lower()

                    is_flask_route = any(
                        dec_clean == pattern
                        or dec_clean.endswith(f".{pattern}")
                        for pattern in [
                            "route",
                            "get",
                            "post",
                            "put",
                            "delete",
                            "patch",
                        ]
                    )

                    if not is_flask_route:
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

                    # Check CSRF
                    csrf_protected = True
                    for d in node.decorator_list:
                        dn = self._extract_name(d).lower()
                        if "csrf.exempt" in dn or "csrf_exempt" in dn:
                            csrf_protected = False
                            break

                    entrypoints.append(
                        FrameworkEntrypoint(
                            entrypoint_id=f"route:{clean_file}:{route_path}",
                            framework_name="flask",
                            route_path=route_path,
                            http_methods=methods,
                            handler_symbol=node.name,
                            handler_qualified_name=f"{clean_file}:{node.name}",
                            location=loc,
                            input_bindings=inputs,
                            auth_guards=auth_guards,
                            csrf_protected=csrf_protected,
                            provenance=RelationshipProvenance.FRAMEWORK_RESOLVED,
                            confidence=1.0,
                        )
                    )

        # Check app.add_url_rule('/path', 'endpoint', view_func) at module level
        if hasattr(tree, "body"):
            for stmt in tree.body:
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    call_name = self._extract_name(stmt.value.func).lower()
                    if call_name.endswith("add_url_rule") and stmt.value.args:
                        route_path = None
                        if isinstance(stmt.value.args[0], ast.Constant) and isinstance(stmt.value.args[0].value, str):
                            route_path = stmt.value.args[0].value

                        handler_name = "<view_func>"
                        if len(stmt.value.args) >= 3 and isinstance(stmt.value.args[2], ast.Name):
                            handler_name = stmt.value.args[2].id
                        for kw in stmt.value.keywords:
                            if kw.arg == "view_func" and isinstance(kw.value, ast.Name):
                                handler_name = kw.value.id

                        if route_path:
                            loc = self.get_source_location(stmt.value, clean_file)
                            entrypoints.append(
                                FrameworkEntrypoint(
                                    entrypoint_id=f"route:{clean_file}:{route_path}",
                                    framework_name="flask",
                                    route_path=route_path,
                                    http_methods=["GET"],
                                    handler_symbol=handler_name,
                                    handler_qualified_name=f"{clean_file}:{handler_name}",
                                    location=loc,
                                    input_bindings=[],
                                    auth_guards=[],
                                    csrf_protected=True,
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
            dec_name = self._extract_name(dec).lower()
            if any(k in dec_name for k in ["login_required", "roles_required", "fresh_login_required", "jwt_required", "permission_required"]):
                guard_kind = AuthGuardKind.AUTHORIZATION if any(k in dec_name for k in ["roles", "permission"]) else AuthGuardKind.AUTHENTICATION
                guards.append(
                    AuthGuardBinding(
                        guard_name=dec_name,
                        guard_kind=guard_kind,
                        status=GuardStatus.ENFORCED,
                        location=self.get_source_location(dec, file_path),
                        mechanism="decorator",
                    )
                )

        return guards

    def detect_inputs(self, node: ast.AST) -> list[InputBinding]:
        inputs: list[InputBinding] = []

        for child in ast.walk(node):
            lineno = getattr(child, "lineno", 1)

            if isinstance(child, ast.Attribute):
                val_name = self._extract_name(child.value).lower()
                attr = child.attr.lower()
                if val_name == "request" or val_name.endswith(".request"):
                    kind = "query_param"
                    if attr in {"form", "json", "data", "values"}:
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
                            expression=f"request.{attr}",
                            line=lineno,
                        )
                    )

            elif isinstance(child, ast.Call):
                fn_name = self._extract_name(child.func).lower()
                if fn_name in {"request.get_json", "request.args.get", "request.form.get", "request.values.get"}:
                    arg_name = "input"
                    if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, str):
                        arg_name = child.args[0].value
                    inputs.append(
                        InputBinding(
                            param_name=arg_name,
                            input_source_kind="body" if "form" in fn_name or "json" in fn_name else "query_param",
                            expression=fn_name,
                            line=lineno,
                        )
                    )

        return inputs
