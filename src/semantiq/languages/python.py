"""Language-aware Python frontend for the Semantic Program Graph."""

from __future__ import annotations

import ast
import contextlib
from pathlib import Path

from semantiq.analysis.frameworks import GLOBAL_FRAMEWORK_REGISTRY
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import (
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RelationshipProvenance,
)
from semantiq.languages.base import FrontendCapabilities, FrontendResult, LanguageFrontend


class PythonFrontend(LanguageFrontend):
    """Deep Python AST frontend generating typed Semantic Program Graph nodes and edges."""

    @property
    def language_id(self) -> str:
        return "python"

    @property
    def file_extensions(self) -> tuple[str, ...]:
        return (".py", ".pyi")

    def get_capabilities(self) -> FrontendCapabilities:
        return FrontendCapabilities(
            language_id="python",
            parsing_coverage="Full Python 3.11+ AST support including async/await, decorators, match/case, type annotations",
            symbol_resolution_coverage="Inter-module symbol lookup, alias resolution, class inheritance resolution",
            call_graph_coverage="Direct static calls, method calls, cross-file imported calls, explicit tracking of dynamic getattr/setattr dispatch",
            data_flow_capabilities="Intra-procedural assignment tracking, parameter-to-return propagation, argument binding across call sites, sanitization neutralization",
            framework_semantics=["Flask", "FastAPI", "Django", "Django REST Framework", "SQLAlchemy", "Requests", "HTTPX"],
            unsupported_syntax_notes=["Metaclass code generation and runtime monkeypatching tracked as unresolved dispatch"],
        )

    def parse_file(
        self,
        file_path: str,
        source_code: str,
        graph: SemanticProgramGraph,
        repo_root: Path,
        source_revision: str = "",
    ) -> FrontendResult:
        clean_file = file_path.replace("\\", "/")
        try:
            tree = ast.parse(source_code, filename=clean_file)
        except (SyntaxError, ValueError) as err:
            return FrontendResult(
                file_path=clean_file,
                language="python",
                parsed_successfully=False,
                errors=[f"AST syntax parsing failure: {err}"],
                gaps=[f"File could not be parsed as valid Python AST: {err}"],
            )

        nodes_before = len(graph.nodes)
        edges_before = sum(len(e) for e in graph.out_edges.values())
        gaps: list[str] = []

        # 1. Create File Node
        file_node_id = f"file:{clean_file}"
        graph.add_node(
            GraphNode(
                id=file_node_id,
                kind=NodeKind.FILE,
                label=Path(clean_file).name,
                file_path=clean_file,
                start_line=1,
                end_line=len(source_code.splitlines()) or 1,
                provenance=RelationshipProvenance.DIRECT_FACT,
                source_revision=source_revision,
            )
        )

        # 2. Extract Imports
        imports_map: dict[str, str] = {}  # local_alias -> full_module_or_symbol
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports_map[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports_map[local] = f"{mod}.{alias.name}" if mod else alias.name

        # 3. Walk classes and functions
        class Visitor(ast.NodeVisitor):
            def __init__(self, outer: PythonFrontend) -> None:
                self.outer = outer
                self.curr_scope: str = file_node_id
                self.curr_symbol_label: str = "<module>"
                self.curr_class: str | None = None

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                class_id = f"class:{clean_file}:{node.name}"
                bases = [self._format_decorator(b) for b in node.bases]
                graph.add_node(
                    GraphNode(
                        id=class_id,
                        kind=NodeKind.CLASS,
                        label=node.name,
                        file_path=clean_file,
                        start_line=node.lineno,
                        end_line=getattr(node, "end_lineno", node.lineno),
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"bases": bases},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=class_id,
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

                prev_scope = self.curr_scope
                prev_class = self.curr_class
                self.curr_scope = class_id
                self.curr_class = node.name

                self.generic_visit(node)

                self.curr_scope = prev_scope
                self.curr_class = prev_class

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._handle_function(node, is_async=False)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._handle_function(node, is_async=True)

            def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
                func_name = node.name
                qname = f"{self.curr_class}.{func_name}" if self.curr_class else func_name
                kind = NodeKind.METHOD if self.curr_class else NodeKind.FUNCTION
                func_id = f"sym:{clean_file}:{qname}"

                params = [arg.arg for arg in node.args.args if arg.arg not in {"self", "cls"}]
                decorators = [self._format_decorator(d) for d in node.decorator_list]

                # Create Function/Method Node
                graph.add_node(
                    GraphNode(
                        id=func_id,
                        kind=kind,
                        label=qname,
                        file_path=clean_file,
                        start_line=node.lineno,
                        end_line=getattr(node, "end_lineno", node.lineno),
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"params": params, "decorators": decorators, "is_async": is_async},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=self.curr_scope,
                        target_id=func_id,
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

                # Route detection
                route_path = None
                is_route = False
                for dec in decorators:
                    dec_lower = dec.lower()
                    if any(k in dec_lower for k in [".route", ".get", ".post", ".put", ".delete", "api_view"]):
                        is_route = True
                        break

                if is_route:
                    route_path = self._extract_route_path(node.decorator_list) or f"/{func_name}"
                    route_id = f"route:{clean_file}:{route_path}"
                    graph.add_node(
                        GraphNode(
                            id=route_id,
                            kind=NodeKind.ROUTE,
                            label=f"Route: {route_path}",
                            file_path=clean_file,
                            start_line=node.lineno,
                            end_line=node.lineno,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                            properties={"route_path": route_path, "handler": qname, "decorators": decorators},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=route_id,
                            target_id=func_id,
                            kind=EdgeKind.CALLS,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )

                    # Auth and Tenant decorators
                    for dec in decorators:
                        dec_lower = dec.lower()
                        if GLOBAL_FRAMEWORK_REGISTRY.is_auth_decorator(dec) or any(
                            k in dec_lower for k in [
                                "login_required", "admin_required", "roles_accepted",
                                "permission_required", "authenticated", "jwt_required",
                                "tenant_scoped", "enforce_tenant", "require_tenant", "tenant_required",
                            ]
                        ):
                            if any(k in dec_lower for k in ["tenant_scoped", "enforce_tenant", "require_tenant", "tenant_required"]):
                                auth_kind = NodeKind.TENANT_CONTEXT
                                auth_edge_kind = EdgeKind.CONTROLS_TENANT
                            elif any(k in dec_lower for k in ["admin", "role", "permission"]):
                                auth_kind = NodeKind.AUTHORIZATION_CHECK
                                auth_edge_kind = EdgeKind.AUTHORIZES
                            else:
                                auth_kind = NodeKind.AUTH_CONTROL
                                auth_edge_kind = EdgeKind.AUTHENTICATES

                            auth_node_id = f"auth:{clean_file}:{func_name}:{dec}"
                            graph.add_node(
                                GraphNode(
                                    id=auth_node_id,
                                    kind=auth_kind,
                                    label=f"Guard: @{dec}",
                                    file_path=clean_file,
                                    start_line=node.lineno,
                                    end_line=node.lineno,
                                    provenance=RelationshipProvenance.DIRECT_FACT,
                                    source_revision=source_revision,
                                )
                            )
                            graph.add_edge(
                                GraphEdge(
                                    source_id=auth_node_id,
                                    target_id=route_id,
                                    kind=auth_edge_kind,
                                    provenance=RelationshipProvenance.DIRECT_FACT,
                                )
                            )

                # Create parameter nodes and bind to function
                for idx, p in enumerate(params):
                    param_id = f"param:{clean_file}:{qname}:{p}"
                    graph.add_node(
                        GraphNode(
                            id=param_id,
                            kind=NodeKind.PARAMETER,
                            label=p,
                            file_path=clean_file,
                            start_line=node.lineno,
                            end_line=node.lineno,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                            properties={"index": idx},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=func_id,
                            target_id=param_id,
                            kind=EdgeKind.DEFINES,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=param_id,
                            target_id=func_id,
                            kind=EdgeKind.DATA_FLOWS_TO,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )

                prev_scope = self.curr_scope
                prev_symbol = self.curr_symbol_label
                self.curr_scope = func_id
                self.curr_symbol_label = qname

                # Walk function body
                for stmt in node.body:
                    self.visit(stmt)

                self.curr_scope = prev_scope
                self.curr_symbol_label = prev_symbol

            def visit_Return(self, node: ast.Return) -> None:
                if node.value is not None:
                    ret_id = f"ret:{clean_file}:{self.curr_symbol_label}:{node.lineno}"
                    graph.add_node(
                        GraphNode(
                            id=ret_id,
                            kind=NodeKind.RETURN_VALUE,
                            label=f"return in {self.curr_symbol_label}",
                            file_path=clean_file,
                            start_line=node.lineno,
                            end_line=getattr(node, "end_lineno", node.lineno),
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=self.curr_scope,
                            target_id=ret_id,
                            kind=EdgeKind.RETURNS_TO,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                lineno = getattr(node, "lineno", 1)

                # Check dynamic dispatch
                if not call_name or call_name in {"getattr", "setattr"}:
                    expr_name = call_name or "dynamic_call"
                    if hasattr(ast, "unparse"):
                        with contextlib.suppress(Exception):
                            expr_name = ast.unparse(node)
                    callsite_id = f"callsite:{clean_file}:{self.curr_symbol_label}:{lineno}"
                    graph.add_node(
                        GraphNode(
                            id=callsite_id,
                            kind=NodeKind.CALL_SITE,
                            label=f"Dynamic Dispatch: {expr_name}",
                            file_path=clean_file,
                            start_line=lineno,
                            end_line=lineno,
                            provenance=RelationshipProvenance.UNRESOLVED,
                            source_revision=source_revision,
                            properties={"is_unresolved": True, "expression": expr_name, "reason": "dynamic_dispatch"},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=self.curr_scope,
                            target_id=callsite_id,
                            kind=EdgeKind.CALLS,
                            provenance=RelationshipProvenance.UNRESOLVED,
                            confidence=0.5,
                        )
                    )
                    gaps.append(f"Line {lineno}: Unresolved dynamic call '{expr_name}' in {self.curr_symbol_label}")
                    self.generic_visit(node)
                    return

                is_self = isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in {"self", "cls"}
                imported_from = imports_map.get(call_name)

                # Record direct calls
                target_symbol_id = f"sym:{call_name}"
                graph.add_edge(
                    GraphEdge(
                        source_id=self.curr_scope,
                        target_id=target_symbol_id,
                        kind=EdgeKind.CALLS,
                        provenance=RelationshipProvenance.STATICALLY_INFERRED,
                        properties={
                            "callee_name": call_name,
                            "line": lineno,
                            "imported_from": imported_from,
                            "is_self_call": is_self,
                            "caller_class": self.curr_class,
                        },
                    )
                )

                # Security Sinks
                if call_name in {"execute", "executemany"}:
                    sink_id = f"sink:sql:{clean_file}:{lineno}"
                    graph.add_node(
                        GraphNode(
                            id=sink_id,
                            kind=NodeKind.QUERY,
                            label=f"SQL Query: {call_name}()",
                            file_path=clean_file,
                            start_line=lineno,
                            end_line=lineno,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                            properties={"sink_expression": f"{call_name}()"},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=self.curr_scope,
                            target_id=sink_id,
                            kind=EdgeKind.QUERIES,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )
                elif call_name in {"system", "popen", "run"}:
                    sink_id = f"sink:exec:{clean_file}:{lineno}"
                    graph.add_node(
                        GraphNode(
                            id=sink_id,
                            kind=NodeKind.PROCESS_EXEC,
                            label=f"Process Exec: {call_name}()",
                            file_path=clean_file,
                            start_line=lineno,
                            end_line=lineno,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                            properties={"sink_expression": f"{call_name}()"},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=self.curr_scope,
                            target_id=sink_id,
                            kind=EdgeKind.REACHES,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )
                elif call_name in {"get", "post", "put", "delete", "request", "urlopen"}:
                    func_val = getattr(node.func, "value", None)
                    v_name = getattr(func_val, "id", "") if func_val else ""
                    if v_name in {"requests", "httpx", "urllib", "client"}:
                        sink_id = f"sink:http:{clean_file}:{lineno}"
                        graph.add_node(
                            GraphNode(
                                id=sink_id,
                                kind=NodeKind.EXTERNAL_REQUEST,
                                label=f"External Request: {v_name}.{call_name}()",
                                file_path=clean_file,
                                start_line=lineno,
                                end_line=lineno,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                                source_revision=source_revision,
                                properties={"sink_expression": f"{v_name}.{call_name}()"},
                            )
                        )
                        graph.add_edge(
                            GraphEdge(
                                source_id=self.curr_scope,
                                target_id=sink_id,
                                kind=EdgeKind.REACHES,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                            )
                        )
                elif call_name in {"send_file", "send_from_directory"}:
                    sink_id = f"sink:file:{clean_file}:{lineno}"
                    graph.add_node(
                        GraphNode(
                            id=sink_id,
                            kind=NodeKind.FILE_OPERATION,
                            label=f"File Send: {call_name}()",
                            file_path=clean_file,
                            start_line=lineno,
                            end_line=lineno,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                            properties={"sink_expression": f"{call_name}()"},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=self.curr_scope,
                            target_id=sink_id,
                            kind=EdgeKind.ACCESSES_RESOURCE,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )

                # Sanitizers
                if call_name in {"int", "float", "escape", "quote", "validate_url", "basename"}:
                    san_id = f"sanitizer:{clean_file}:{lineno}:{call_name}"
                    graph.add_node(
                        GraphNode(
                            id=san_id,
                            kind=NodeKind.SANITIZER,
                            label=f"Sanitizer: {call_name}()",
                            file_path=clean_file,
                            start_line=lineno,
                            end_line=lineno,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=self.curr_scope,
                            target_id=san_id,
                            kind=EdgeKind.SANITIZES,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )

                # Check for session/context tenant lookup: e.g. session.get("tenant_id")
                if call_name == "get":
                    func_val = getattr(node.func, "value", None)
                    v_name = getattr(func_val, "id", "") if func_val else ""
                    if (
                        v_name in {"session", "request", "current_user", "ctx", "context", "auth"}
                        and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                    ):
                        key = node.args[0].value.lower()
                        if any(k in key for k in ["tenant", "org", "workspace"]):
                                tenant_node_id = f"tenant:{clean_file}:{lineno}:{v_name}_{key}"
                                graph.add_node(
                                    GraphNode(
                                        id=tenant_node_id,
                                        kind=NodeKind.TENANT_CONTEXT,
                                        label=f"Tenant Context: {v_name}.{key}",
                                        file_path=clean_file,
                                        start_line=lineno,
                                        end_line=lineno,
                                        provenance=RelationshipProvenance.DIRECT_FACT,
                                        source_revision=source_revision,
                                        properties={"source": v_name, "key": key},
                                    )
                                )
                                graph.add_edge(
                                    GraphEdge(
                                        source_id=tenant_node_id,
                                        target_id=self.curr_scope,
                                        kind=EdgeKind.CONTROLS_TENANT,
                                        provenance=RelationshipProvenance.DIRECT_FACT,
                                    )
                                )

                self.generic_visit(node)

            def visit_Attribute(self, node: ast.Attribute) -> None:
                v_name = getattr(node.value, "id", "")
                attr_name = node.attr.lower()
                if (v_name in {"current_user", "user", "session", "auth"} or "user" in v_name) and any(
                    k in attr_name for k in ["tenant", "org", "workspace"]
                ):
                    lineno = getattr(node, "lineno", 1)
                    tenant_node_id = f"tenant:{clean_file}:{lineno}:{v_name}_{attr_name}"
                    graph.add_node(
                        GraphNode(
                            id=tenant_node_id,
                            kind=NodeKind.TENANT_CONTEXT,
                            label=f"Tenant Context: {v_name}.{attr_name}",
                            file_path=clean_file,
                            start_line=lineno,
                            end_line=lineno,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                            source_revision=source_revision,
                            properties={"source": v_name, "key": attr_name},
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=tenant_node_id,
                            target_id=self.curr_scope,
                            kind=EdgeKind.CONTROLS_TENANT,
                            provenance=RelationshipProvenance.DIRECT_FACT,
                        )
                    )
                self.generic_visit(node)

            def visit_Subscript(self, node: ast.Subscript) -> None:
                v_name = getattr(node.value, "id", "")
                if v_name in {"session", "request", "g", "ctx", "context", "auth"}:
                    slice_node = node.slice
                    key_val = getattr(slice_node, "value", None)
                    if isinstance(key_val, str) and any(k in key_val.lower() for k in ["tenant", "org", "workspace"]):
                        lineno = getattr(node, "lineno", 1)
                        tenant_node_id = f"tenant:{clean_file}:{lineno}:{v_name}_{key_val}"
                        graph.add_node(
                            GraphNode(
                                id=tenant_node_id,
                                kind=NodeKind.TENANT_CONTEXT,
                                label=f"Tenant Context: {v_name}[{key_val}]",
                                file_path=clean_file,
                                start_line=lineno,
                                end_line=lineno,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                                source_revision=source_revision,
                                properties={"source": v_name, "key": key_val},
                            )
                        )
                        graph.add_edge(
                            GraphEdge(
                                source_id=tenant_node_id,
                                target_id=self.curr_scope,
                                kind=EdgeKind.CONTROLS_TENANT,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                            )
                        )
                self.generic_visit(node)

            def _format_decorator(self, d_node: ast.AST) -> str:
                if isinstance(d_node, ast.Name):
                    return d_node.id
                elif isinstance(d_node, ast.Attribute):
                    return f"{self._format_decorator(d_node.value)}.{d_node.attr}"
                elif isinstance(d_node, ast.Call):
                    return self._format_decorator(d_node.func)
                return ""

            def _extract_route_path(self, decs: list[ast.expr]) -> str | None:
                for d in decs:
                    if isinstance(d, ast.Call) and d.args:
                        arg0 = d.args[0]
                        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                            return arg0.value
                return None

        visitor = Visitor(self)
        visitor.visit(tree)

        nodes_created = len(graph.nodes) - nodes_before
        edges_created = sum(len(e) for e in graph.out_edges.values()) - edges_before

        return FrontendResult(
            file_path=clean_file,
            language="python",
            parsed_successfully=True,
            nodes_created=nodes_created,
            edges_created=edges_created,
            gaps=gaps,
        )
