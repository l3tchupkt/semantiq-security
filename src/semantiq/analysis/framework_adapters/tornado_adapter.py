"""Tornado web and WebSocket framework adapter."""

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


class TornadoAdapter(FrameworkAdapter):
    """Adapter for Tornado RequestHandler, WebSocketHandler, and Application route tables."""

    @property
    def framework_name(self) -> str:
        return "tornado"

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

        # Track Application route registrations: pattern -> handler_class_name
        app_routes: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._extract_name(node.func)
                if "Application" in call_name and node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, (ast.List, ast.Tuple)):
                        for route_entry in arg0.elts:
                            if isinstance(route_entry, (ast.Tuple, ast.List)) and len(route_entry.elts) >= 2:
                                pat_el = route_entry.elts[0]
                                handler_el = route_entry.elts[1]
                                pat = "/"
                                if isinstance(pat_el, ast.Constant) and isinstance(pat_el.value, str):
                                    pat = pat_el.value
                                h_name = self._extract_name(handler_el)
                                if h_name:
                                    app_routes[h_name] = pat

        # Walk classes to find RequestHandler / WebSocketHandler subclasses
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                base_names = [self._extract_name(b) for b in node.bases]
                is_req_handler = any(
                    "RequestHandler" in b or "WebSocketHandler" in b or "Handler" in b
                    for b in base_names
                )
                is_ws = any("WebSocketHandler" in b for b in base_names)

                if not is_req_handler:
                    continue

                route_path = app_routes.get(node.name, f"/{node.name.lower().removesuffix('handler')}")

                # Check methods inside the class
                http_methods: list[str] = []
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        fn_name = item.name.lower()
                        if fn_name in {"get", "post", "put", "delete", "head", "options", "patch"}:
                            http_methods.append(fn_name.upper())
                        elif fn_name in {"open", "on_message"}:
                            is_ws = True
                            http_methods.append("WEBSOCKET")

                if not http_methods:
                    http_methods = ["GET"] if not is_ws else ["WEBSOCKET"]

                loc = self.get_source_location(node, clean_file)
                inputs = self.detect_inputs(node)
                auth_guards = self.detect_auth_guards(node, clean_file)

                # Check CSRF
                csrf_protected = True
                for item in node.body:
                    if (
                        isinstance(item, ast.FunctionDef)
                        and item.name == "check_xsrf_cookie"
                        and len(item.body) == 1
                        and isinstance(item.body[0], ast.Pass)
                    ):
                        csrf_protected = False

                entrypoints.append(
                    FrameworkEntrypoint(
                        entrypoint_id=f"route:{clean_file}:{route_path}",
                        framework_name="tornado",
                        route_path=route_path,
                        http_methods=http_methods,
                        handler_symbol=node.name,
                        handler_qualified_name=f"{clean_file}:{node.name}",
                        location=loc,
                        input_bindings=inputs,
                        auth_guards=auth_guards,
                        csrf_protected=csrf_protected,
                        is_websocket=is_ws,
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

        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in child.decorator_list:
                    dn = self._extract_name(dec).lower()
                    if "authenticated" in dn or "tornado.web.authenticated" in dn:
                        guards.append(
                            AuthGuardBinding(
                                guard_name=dn,
                                guard_kind=AuthGuardKind.AUTHENTICATION,
                                status=GuardStatus.ENFORCED,
                                location=self.get_source_location(dec, file_path),
                                mechanism="decorator",
                            )
                        )

            # Check get_current_user override
            if isinstance(child, ast.FunctionDef) and child.name == "get_current_user":
                guards.append(
                    AuthGuardBinding(
                        guard_name="get_current_user",
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

            if isinstance(child, ast.Call):
                fn_name = self._extract_name(child.func).lower()
                if any(
                    fn_name.endswith(k)
                    for k in [
                        "get_argument",
                        "get_arguments",
                        "get_query_argument",
                        "get_body_argument",
                    ]
                ):
                    arg_name = "argument"
                    if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, str):
                        arg_name = child.args[0].value

                    kind = "body" if "body" in fn_name else "query_param"
                    inputs.append(
                        InputBinding(
                            param_name=arg_name,
                            input_source_kind=kind,
                            expression=fn_name,
                            line=lineno,
                        )
                    )

            elif isinstance(child, ast.Attribute):
                attr = child.attr.lower()
                val_name = self._extract_name(child.value).lower()
                if "self.request" in val_name or val_name == "request":
                    kind = "query_param"
                    if attr in {"body", "arguments"}:
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
                            expression=f"self.request.{attr}",
                            line=lineno,
                        )
                    )

        return inputs
