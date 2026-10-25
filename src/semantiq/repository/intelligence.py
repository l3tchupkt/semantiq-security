"""Repository intelligence layer: symbol indexing, import graphs, call graphs, and framework models."""

from __future__ import annotations

import ast
import contextlib
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from semantiq.analysis.frameworks import GLOBAL_FRAMEWORK_REGISTRY
from semantiq.models import (
    AuthBoundary,
    CoverageReport,
    SeverityLevel,
    UnresolvedCall,
    VulnerabilityCategory,
)
from semantiq.repository.safepath import resolve_safe_path


@dataclass
class IndexedSymbol:
    """An indexed code symbol (function, method, class) representing a deterministic fact."""

    name: str
    qualified_name: str
    kind: str  # "function", "async_function", "method", "class"
    file_path: str
    start_line: int
    end_line: int
    parameters: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None
    is_entry_point: bool = False
    framework: str | None = None
    http_method: str | None = None
    route_path: str | None = None


@dataclass
class IndexedImport:
    """Import relationship between modules."""

    source_file: str
    imported_module: str
    imported_symbol: str
    local_alias: str
    is_wildcard: bool = False


@dataclass
class CallEdge:
    """Inferred call relationship from caller to callee."""

    caller_file: str
    caller_symbol: str
    callee_name: str
    line: int
    resolved_target_file: str | None = None
    resolved_target_symbol: str | None = None


@dataclass
class SecuritySinkLocation:
    """Deterministic record of a dangerous security sink invocation."""

    category: VulnerabilityCategory
    rule_id: str
    sink_expression: str
    file_path: str
    line: int
    symbol_name: str
    severity: SeverityLevel
    explanation: str


@dataclass
class FileIndexMetadata:
    """Metadata and content hash for incremental scan change detection."""

    relative_path: str
    sha256: str
    size_bytes: int
    language: str


class RepositoryIntelligence:
    """Comprehensive repository intelligence model distinguishing facts, inferences, and hypotheses."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.file_metadata: dict[str, FileIndexMetadata] = {}
        self.symbols: dict[str, list[IndexedSymbol]] = {}  # file_path -> symbols
        self.imports: dict[str, list[IndexedImport]] = {}  # file_path -> imports
        self.call_graph: list[CallEdge] = []
        self.security_sinks: list[SecuritySinkLocation] = []
        self.frameworks_detected: set[str] = set()
        self.security_configs: dict[str, Any] = {}
        self.unresolved_calls: list[UnresolvedCall] = []
        self.auth_boundaries: list[AuthBoundary] = []
        self.multi_tenant_indicators: set[str] = set()
        self.global_middleware: list[str] = []
        self.parsed_files_count: int = 0
        self.failed_parsing_files: list[str] = []
        # Incremental scan content-hash cache: rel_path -> (sha256, symbols, imports, auth_boundaries)
        self._content_cache: dict[str, tuple[str, list[IndexedSymbol], list[IndexedImport], list[AuthBoundary]]] = {}

    def index_repository(self, in_scope_files: list[str]) -> None:
        """Deterministically index all in-scope files in the repository using content-hash caching."""
        for rel_path in in_scope_files:
            try:
                full_path = resolve_safe_path(self.repo_root, rel_path)
            except Exception:
                continue

            if not full_path.exists() or not full_path.is_file():
                continue

            try:
                content_bytes = full_path.read_bytes()
                sha = hashlib.sha256(content_bytes).hexdigest()
                content = content_bytes.decode("utf-8", errors="replace")
            except OSError:
                continue

            lang = "python" if rel_path.endswith((".py", ".pyi")) else (
                "javascript" if rel_path.endswith((".js", ".jsx", ".mjs", ".cjs")) else (
                    "typescript" if rel_path.endswith((".ts", ".tsx")) else "other"
                )
            )

            self.file_metadata[rel_path] = FileIndexMetadata(
                relative_path=rel_path,
                sha256=sha,
                size_bytes=len(content_bytes),
                language=lang,
            )

            if lang == "python":
                # Check incremental content cache
                cached = self._content_cache.get(rel_path)
                if cached and cached[0] == sha:
                    self.symbols[rel_path] = list(cached[1])
                    self.imports[rel_path] = list(cached[2])
                    self.auth_boundaries.extend(cached[3])
                    self.parsed_files_count += 1
                else:
                    self._index_python_file(rel_path, content, sha)

    def _index_python_file(self, rel_path: str, source_code: str, sha: str = "") -> None:
        """Parse Python source and extract facts (symbols, imports, calls, sinks, routes)."""
        try:
            tree = ast.parse(source_code, filename=rel_path)
            self.parsed_files_count += 1
        except (SyntaxError, ValueError):
            self.failed_parsing_files.append(rel_path)
            return

        file_symbols: list[IndexedSymbol] = []
        file_imports: list[IndexedImport] = []
        file_auth_boundaries: list[AuthBoundary] = []

        for node in ast.iter_child_nodes(tree):
            # Imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.append(
                        IndexedImport(
                            source_file=rel_path,
                            imported_module=alias.name,
                            imported_symbol="",
                            local_alias=alias.asname or alias.name,
                        )
                    )
                    if "flask" in alias.name:
                        self.frameworks_detected.add("flask")
                    elif "fastapi" in alias.name:
                        self.frameworks_detected.add("fastapi")
                    elif "django" in alias.name:
                        self.frameworks_detected.add("django")

            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if "flask" in mod:
                    self.frameworks_detected.add("flask")
                elif "fastapi" in mod:
                    self.frameworks_detected.add("fastapi")
                elif "django" in mod:
                    self.frameworks_detected.add("django")

                for alias in node.names:
                    file_imports.append(
                        IndexedImport(
                            source_file=rel_path,
                            imported_module=mod,
                            imported_symbol=alias.name,
                            local_alias=alias.asname or alias.name,
                            is_wildcard=(alias.name == "*"),
                        )
                    )

            # Class definitions
            elif isinstance(node, ast.ClassDef):
                file_symbols.append(
                    IndexedSymbol(
                        name=node.name,
                        qualified_name=node.name,
                        kind="class",
                        file_path=rel_path,
                        start_line=node.lineno,
                        end_line=getattr(node, "end_lineno", node.lineno),
                        docstring=ast.get_docstring(node),
                    )
                )
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._index_function(
                            item,
                            rel_path,
                            parent_class=node.name,
                            out_symbols=file_symbols,
                            out_auth_boundaries=file_auth_boundaries,
                        )

            # Top-level Functions
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._index_function(
                    node,
                    rel_path,
                    parent_class=None,
                    out_symbols=file_symbols,
                    out_auth_boundaries=file_auth_boundaries,
                )

        self.symbols[rel_path] = file_symbols
        self.imports[rel_path] = file_imports
        if sha:
            self._content_cache[rel_path] = (sha, file_symbols, file_imports, file_auth_boundaries)

        # Walk entire file AST for calls and sinks
        self._index_file_calls_and_sinks(tree, rel_path)

    def _index_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_path: str,
        parent_class: str | None,
        out_symbols: list[IndexedSymbol],
        out_auth_boundaries: list[AuthBoundary],
    ) -> None:
        params = [arg.arg for arg in node.args.args]
        decorators: list[str] = []

        is_entry = False
        framework = None
        http_method = None
        route_path = None

        for dec_node in node.decorator_list:
            dec = self._format_decorator(dec_node)
            decorators.append(dec)
            dec_lower = dec.lower()
            if any(k in dec_lower for k in [".route", ".get", ".post", ".put", ".delete", "api_view", "action"]):
                is_entry = True
                if "app.route" in dec_lower or "bp.route" in dec_lower or "blueprint" in dec_lower:
                    framework = "flask"
                elif "router." in dec_lower or "app.get" in dec_lower or "app.post" in dec_lower:
                    framework = "fastapi"
                elif "api_view" in dec_lower:
                    framework = "django_rest_framework"

                # Extract route path if constant in decorator args
                if (
                    isinstance(dec_node, ast.Call)
                    and dec_node.args
                    and isinstance(dec_node.args[0], ast.Constant)
                    and isinstance(dec_node.args[0].value, str)
                ):
                    route_path = dec_node.args[0].value

                # Extract HTTP method if available
                for m in ["get", "post", "put", "delete", "patch"]:
                    if f".{m}" in dec_lower:
                        http_method = m.upper()
                        break

        qname = f"{parent_class}.{node.name}" if parent_class else node.name
        kind = "method" if parent_class else ("async_function" if isinstance(node, ast.AsyncFunctionDef) else "function")

        if is_entry:
            auth_decs = [
                d for d in decorators
                if GLOBAL_FRAMEWORK_REGISTRY.is_auth_decorator(d)
                or any(k in d.lower() for k in [
                    "login_required", "admin_required", "permission_required",
                    "roles_accepted", "roles_required", "jwt_required", "token_required",
                    "authenticated", "requires_auth"
                ])
            ]
            is_auth = len(auth_decs) > 0
            is_admin = any("admin" in d.lower() or "superuser" in d.lower() for d in decorators)
            is_tenant = any(p in {"tenant_id", "org_id", "workspace_id"} for p in params)
            boundary = AuthBoundary(
                route_path=route_path or f"/{node.name}",
                handler_name=qname,
                file_path=rel_path,
                line=node.lineno,
                http_methods=[http_method] if http_method else ["GET"],
                is_authenticated=is_auth,
                auth_decorators=auth_decs,
                is_admin_only=is_admin,
                is_tenant_scoped=is_tenant,
            )
            self.auth_boundaries.append(boundary)
            out_auth_boundaries.append(boundary)

        out_symbols.append(
            IndexedSymbol(
                name=node.name,
                qualified_name=qname,
                kind=kind,
                file_path=rel_path,
                start_line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                parameters=params,
                decorators=decorators,
                docstring=ast.get_docstring(node),
                is_entry_point=is_entry,
                framework=framework,
                http_method=http_method,
                route_path=route_path,
            )
        )

    def _format_decorator(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._format_decorator(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._format_decorator(node.func)
        return ""

    def _index_file_calls_and_sinks(self, tree: ast.AST, rel_path: str) -> None:
        class CallVisitor(ast.NodeVisitor):
            def __init__(self, outer: RepositoryIntelligence) -> None:
                self.outer = outer
                self.curr = "<module>"

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                prev = self.curr
                self.curr = node.name
                self.generic_visit(node)
                self.curr = prev

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                prev = self.curr
                self.curr = node.name
                self.generic_visit(node)
                self.curr = prev

            def visit_Assign(self, node: ast.Assign) -> None:
                for target in node.targets:
                    t_name = getattr(target, "id", "") or getattr(target, "attr", "")
                    if any(k in t_name.lower() for k in ["tenant_id", "org_id", "organization_id", "workspace_id"]):
                        self.outer.multi_tenant_indicators.add(t_name)
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                lineno = getattr(node, "lineno", 1)

                # Record call edge or unresolved call
                if call_name and call_name != "getattr":
                    self.outer.call_graph.append(
                        CallEdge(
                            caller_file=rel_path,
                            caller_symbol=self.curr,
                            callee_name=call_name,
                            line=lineno,
                        )
                    )
                if not call_name or call_name in {"getattr", "setattr"}:
                    expr_name = call_name or "dynamic_call"
                    if hasattr(ast, "unparse"):
                        with contextlib.suppress(Exception):
                            expr_name = ast.unparse(node)
                    self.outer.unresolved_calls.append(
                        UnresolvedCall(
                            file_path=rel_path,
                            line=lineno,
                            caller_symbol=self.curr,
                            call_expression=expr_name,
                            reason="dynamic_dispatch_or_unresolved_expression",
                        )
                    )

                # Record security sink facts
                if call_name in {"execute", "executemany"}:
                    self.outer.security_sinks.append(
                        SecuritySinkLocation(
                            category=VulnerabilityCategory.SQL_INJECTION,
                            rule_id="SQ-PY-002",
                            sink_expression=f"{call_name}()",
                            file_path=rel_path,
                            line=lineno,
                            symbol_name=self.curr,
                            severity=SeverityLevel.HIGH,
                            explanation="Database SQL execution sink",
                        )
                    )
                elif call_name in {"system", "popen"}:
                    self.outer.security_sinks.append(
                        SecuritySinkLocation(
                            category=VulnerabilityCategory.COMMAND_INJECTION,
                            rule_id="SQ-PY-001",
                            sink_expression=f"os.{call_name}()",
                            file_path=rel_path,
                            line=lineno,
                            symbol_name=self.curr,
                            severity=SeverityLevel.CRITICAL,
                            explanation="Operating system command execution sink",
                        )
                    )
                elif call_name in {"eval", "exec"}:
                    self.outer.security_sinks.append(
                        SecuritySinkLocation(
                            category=VulnerabilityCategory.CODE_INJECTION,
                            rule_id="SQ-PY-009",
                            sink_expression=f"{call_name}()",
                            file_path=rel_path,
                            line=lineno,
                            symbol_name=self.curr,
                            severity=SeverityLevel.CRITICAL,
                            explanation="Dynamic code evaluation sink",
                        )
                    )
                elif call_name in {"loads", "load"}:
                    func_val = getattr(node.func, "value", None)
                    if func_val is not None:
                        val_name = getattr(func_val, "id", "")
                        if val_name in {"pickle", "_pickle", "cPickle", "yaml"}:
                            self.outer.security_sinks.append(
                                SecuritySinkLocation(
                                    category=VulnerabilityCategory.UNSAFE_DESERIALIZATION,
                                    rule_id="SQ-PY-003",
                                    sink_expression=f"{val_name}.{call_name}()",
                                    file_path=rel_path,
                                    line=lineno,
                                    symbol_name=self.curr,
                                    severity=SeverityLevel.CRITICAL,
                                    explanation=f"Unsafe deserialization sink via {val_name}",
                                )
                            )

                self.generic_visit(node)

        visitor = CallVisitor(self)
        visitor.visit(tree)

    def compute_coverage(self, in_scope_files: list[str]) -> CoverageReport:
        """Compute actionable coverage report with explicit gap accounting."""
        total_in_scope = len(in_scope_files)
        parsed = self.parsed_files_count
        skipped = max(0, total_in_scope - parsed)
        coverage_ratio = (parsed / total_in_scope * 100.0) if total_in_scope > 0 else 100.0

        gap_notes: list[str] = []
        if self.failed_parsing_files:
            gap_notes.append(f"{len(self.failed_parsing_files)} files could not be parsed as valid AST syntax")
        if self.unresolved_calls:
            gap_notes.append(f"{len(self.unresolved_calls)} call sites involve dynamic dispatch or unresolved external targets")

        languages_detected = {m.language for m in self.file_metadata.values()}
        unsupported = [lang for lang in languages_detected if lang not in {"python", "javascript", "typescript"}]
        if unsupported:
            gap_notes.append(f"Languages requiring specialized external parsers: {', '.join(unsupported)}")

        return CoverageReport(
            total_files_discovered=len(self.file_metadata),
            in_scope_files=total_in_scope,
            parsed_files=parsed,
            skipped_files=skipped,
            failed_parsing_files=list(self.failed_parsing_files),
            languages_supported=["python", "javascript", "typescript"],
            languages_unsupported=unsupported,
            unresolved_calls_count=len(self.unresolved_calls),
            coverage_percentage=round(coverage_ratio, 2),
            gap_notes=gap_notes,
        )
