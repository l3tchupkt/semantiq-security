"""Django framework URL configuration, view, and permission adapter."""

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


class DjangoAdapter(FrameworkAdapter):
    """Adapter for Django urlpatterns, function views, CBVs, and DRF viewsets."""

    @property
    def framework_name(self) -> str:
        return "django"

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
            # Check urlpatterns list: path('url/', view_fn) or re_path(r'^url/', ...)
            if isinstance(node, ast.Assign):
                is_urlpatterns = any(
                    isinstance(t, ast.Name) and t.id == "urlpatterns"
                    for t in node.targets
                )
                if is_urlpatterns and isinstance(node.value, (ast.List, ast.Tuple)):
                    for el in node.value.elts:
                        if isinstance(el, ast.Call):
                            call_name = self._extract_name(el.func)
                            if call_name in {"path", "re_path", "url"} and el.args:
                                route_path = "/"
                                if isinstance(el.args[0], ast.Constant) and isinstance(el.args[0].value, str):
                                    route_path = el.args[0].value

                                handler_name = "<view>"
                                if len(el.args) >= 2:
                                    handler_name = self._extract_name(el.args[1])

                                loc = self.get_source_location(el, clean_file)
                                entrypoints.append(
                                    FrameworkEntrypoint(
                                        entrypoint_id=f"route:{clean_file}:{route_path}",
                                        framework_name="django",
                                        route_path=route_path,
                                        http_methods=["GET", "POST"],
                                        handler_symbol=handler_name,
                                        handler_qualified_name=f"{clean_file}:{handler_name}",
                                        location=loc,
                                        input_bindings=[],
                                        auth_guards=[],
                                        csrf_protected=True,
                                        provenance=RelationshipProvenance.FRAMEWORK_RESOLVED,
                                        confidence=1.0,
                                    )
                                )

            # Check DRF @api_view or @action
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = self._extract_name(dec)
                    if "api_view" in dec_name or "action" in dec_name:
                        methods = ["GET"]
                        if isinstance(dec, ast.Call) and dec.args:
                            arg0 = dec.args[0]
                            if isinstance(arg0, (ast.List, ast.Tuple)):
                                extracted = [
                                    el.value.upper()
                                    for el in arg0.elts
                                    if isinstance(el, ast.Constant) and isinstance(el.value, str)
                                ]
                                if extracted:
                                    methods = extracted

                        loc = self.get_source_location(node, clean_file)
                        inputs = self.detect_inputs(node)
                        auth_guards = self.detect_auth_guards(node, clean_file)

                        # Check CSRF exempt
                        csrf_protected = True
                        for d in node.decorator_list:
                            dn = self._extract_name(d).lower()
                            if "csrf_exempt" in dn:
                                csrf_protected = False
                                break

                        entrypoints.append(
                            FrameworkEntrypoint(
                                entrypoint_id=f"entry:django:{clean_file}:/{node.name}",
                                framework_name="django",
                                route_path=f"/{node.name}",
                                http_methods=methods,
                                handler_symbol=node.name,
                                handler_qualified_name=f"{clean_file}:{node.name}",
                                location=loc,
                                input_bindings=inputs,
                                auth_guards=auth_guards,
                                csrf_protected=csrf_protected,
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
            if any(k in dec_name for k in ["login_required", "permission_required", "user_passes_test"]):
                guard_kind = AuthGuardKind.AUTHORIZATION if "permission" in dec_name else AuthGuardKind.AUTHENTICATION
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
                attr = child.attr
                if val_name == "request" or val_name.endswith(".request"):
                    kind = "query_param"
                    if attr in {"POST", "data", "body"}:
                        kind = "body"
                    elif attr in {"META", "headers"}:
                        kind = "header"
                    elif attr in {"COOKIES"}:
                        kind = "cookie"
                    elif attr in {"FILES"}:
                        kind = "file"

                    inputs.append(
                        InputBinding(
                            param_name=attr,
                            input_source_kind=kind,
                            expression=f"request.{attr}",
                            line=lineno,
                        )
                    )

        return inputs
