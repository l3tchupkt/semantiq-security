"""Repository intelligence layer: symbol indexing, import graphs, call graphs, and framework models."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from semantiq.models import SeverityLevel, VulnerabilityCategory
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

    def index_repository(self, in_scope_files: list[str]) -> None:
        """Deterministically index all in-scope files in the repository."""
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
                self._index_python_file(rel_path, content)

    def _index_python_file(self, rel_path: str, source_code: str) -> None:
        """Parse Python source and extract facts (symbols, imports, calls, sinks, routes)."""
        try:
            tree = ast.parse(source_code, filename=rel_path)
        except (SyntaxError, ValueError):
            return

        file_symbols: list[IndexedSymbol] = []
        file_imports: list[IndexedImport] = []

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
                        self._index_function(item, rel_path, parent_class=node.name, out_symbols=file_symbols)

            # Top-level Functions
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._index_function(node, rel_path, parent_class=None, out_symbols=file_symbols)

        self.symbols[rel_path] = file_symbols
        self.imports[rel_path] = file_imports

        # Walk entire file AST for calls and sinks
        self._index_file_calls_and_sinks(tree, rel_path)

    def _index_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        rel_path: str,
        parent_class: str | None,
        out_symbols: list[IndexedSymbol],
    ) -> None:
        params = [arg.arg for arg in node.args.args]
        decorators = [self._format_decorator(d) for d in node.decorator_list]

        is_entry = False
        framework = None
        http_method = None
        route_path = None

        for dec in decorators:
            dec_lower = dec.lower()
            if any(k in dec_lower for k in [".route", ".get", ".post", ".put", ".delete", "api_view", "action"]):
                is_entry = True
                if "app.route" in dec_lower or "bp.route" in dec_lower or "blueprint" in dec_lower:
                    framework = "flask"
                elif "router." in dec_lower or "app.get" in dec_lower or "app.post" in dec_lower:
                    framework = "fastapi"
                elif "api_view" in dec_lower:
                    framework = "django_rest_framework"

                # Extract HTTP method if available
                for m in ["get", "post", "put", "delete", "patch"]:
                    if f".{m}" in dec_lower:
                        http_method = m.upper()
                        break

        qname = f"{parent_class}.{node.name}" if parent_class else node.name
        kind = "method" if parent_class else ("async_function" if isinstance(node, ast.AsyncFunctionDef) else "function")

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

            def visit_Call(self, node: ast.Call) -> None:
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                lineno = getattr(node, "lineno", 1)

                # Record call edge
                if call_name:
                    self.outer.call_graph.append(
                        CallEdge(
                            caller_file=rel_path,
                            caller_symbol=self.curr,
                            callee_name=call_name,
                            line=lineno,
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
