"""Inter-procedural analysis and repository-wide function summaries."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from semantiq.models import SeverityLevel, VulnerabilityCategory


@dataclass
class SinkReach:
    """Records a parameter reaching a dangerous sink inside a function."""

    param_index: int
    param_name: str
    rule_id: str
    category: VulnerabilityCategory
    severity: SeverityLevel
    explanation: str
    line: int
    code_snippet: str
    file_path: str = ""


@dataclass
class FunctionSummary:
    """Summary of a function's taint transfer and internal sinks."""

    name: str
    module_name: str
    file_path: str
    params: list[str]
    # Parameter indices (0-based) that propagate into return value
    returns_taint_from_params: set[int] = field(default_factory=set)
    # Sinks reached within this function that consume parameter values
    internal_sinks: list[SinkReach] = field(default_factory=list)


class FunctionSummaryExtractor(ast.NodeVisitor):
    """Extracts taint transfer characteristics and internal sinks from a function definition."""

    def __init__(self, file_path: str, module_name: str, source_lines: list[str]) -> None:
        self.file_path = file_path.replace("\\", "/")
        self.module_name = module_name
        self.source_lines = source_lines
        self.summaries: dict[str, FunctionSummary] = {}
        self._current_summary: FunctionSummary | None = None
        self._param_names: list[str] = []
        self._tainted_vars: dict[str, set[int]] = {}  # var_name -> set of param indices

    def _get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        params: list[str] = []
        param_map: dict[str, set[int]] = {}
        for idx, arg in enumerate(node.args.args):
            if arg.arg not in {"self", "cls"}:
                params.append(arg.arg)
                param_map[arg.arg] = {idx}

        summary = FunctionSummary(
            name=node.name,
            module_name=self.module_name,
            file_path=self.file_path,
            params=params,
        )

        prev_summary = self._current_summary
        prev_tainted = self._tainted_vars
        self._current_summary = summary
        self._tainted_vars = dict(param_map)

        for stmt in node.body:
            self._analyze_statement(stmt)

        self.summaries[node.name] = summary
        self._current_summary = prev_summary
        self._tainted_vars = prev_tainted

    def _expr_taint_params(self, expr: ast.AST) -> set[int]:
        """Determine which parameters taint a given AST expression."""
        tainting_params: set[int] = set()

        if isinstance(expr, ast.Name):
            if expr.id in self._tainted_vars:
                tainting_params.update(self._tainted_vars[expr.id])

        elif isinstance(expr, ast.JoinedStr):
            for val in expr.values:
                if isinstance(val, ast.FormattedValue):
                    tainting_params.update(self._expr_taint_params(val.value))

        elif isinstance(expr, ast.BinOp):
            tainting_params.update(self._expr_taint_params(expr.left))
            tainting_params.update(self._expr_taint_params(expr.right))

        elif isinstance(expr, ast.Call):
            for arg in expr.args:
                tainting_params.update(self._expr_taint_params(arg))
            for kw in expr.keywords:
                tainting_params.update(self._expr_taint_params(kw.value))

        return tainting_params

    def _analyze_statement(self, stmt: ast.AST) -> None:
        if self._current_summary is None:
            return

        if isinstance(stmt, ast.Assign):
            taint = self._expr_taint_params(stmt.value)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    if taint:
                        self._tainted_vars[target.id] = set(taint)
                    else:
                        self._tainted_vars.pop(target.id, None)

        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                taint = self._expr_taint_params(stmt.value)
                if taint:
                    self._tainted_vars.setdefault(stmt.target.id, set()).update(taint)

        elif isinstance(stmt, ast.Return) and stmt.value:
            taint = self._expr_taint_params(stmt.value)
            self._current_summary.returns_taint_from_params.update(taint)

        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            self._check_sink_call(stmt.value)

        # Recursively analyze nested control flow blocks
        elif isinstance(stmt, ast.If):
            for s in stmt.body:
                self._analyze_statement(s)
            for s in stmt.orelse:
                self._analyze_statement(s)

        elif isinstance(stmt, ast.Try):
            for s in stmt.body:
                self._analyze_statement(s)
            for handler in stmt.handlers:
                for s in handler.body:
                    self._analyze_statement(s)
            for s in stmt.finalbody:
                self._analyze_statement(s)

        elif isinstance(stmt, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)):
            for s in stmt.body:
                self._analyze_statement(s)
            for s in getattr(stmt, "orelse", []):
                self._analyze_statement(s)

    def _check_sink_call(self, call_node: ast.Call) -> None:
        if self._current_summary is None:
            return

        call_name = ""
        if isinstance(call_node.func, ast.Name):
            call_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            call_name = call_node.func.attr

        lineno = getattr(call_node, "lineno", 1)
        snippet = self._get_line(lineno).strip()

        # 1. SQL execution sink
        if call_name in {"execute", "executemany", "raw", "extra"} and call_node.args:
            # Check if parameterized (passing parameters tuple/dict suppresses raw injection)
            has_params = len(call_node.args) >= 2 or any(k.arg in {"params", "parameters"} for k in call_node.keywords)
            if not has_params:
                taint = self._expr_taint_params(call_node.args[0])
                for param_idx in taint:
                    pname = self._current_summary.params[param_idx] if param_idx < len(self._current_summary.params) else f"arg_{param_idx}"
                    self._current_summary.internal_sinks.append(
                        SinkReach(
                            param_index=param_idx,
                            param_name=pname,
                            rule_id="SQ-PY-002",
                            category=VulnerabilityCategory.SQL_INJECTION,
                            severity=SeverityLevel.HIGH,
                            explanation=f"Function parameter '{pname}' reaches database execute() sink in {self._current_summary.name}",
                            line=lineno,
                            code_snippet=snippet,
                            file_path=self.file_path,
                        )
                    )

        # 2. Command execution sink
        elif call_name in {"system", "popen", "Popen", "run", "call", "check_output"} and call_node.args:
            taint = self._expr_taint_params(call_node.args[0])
            for param_idx in taint:
                pname = self._current_summary.params[param_idx] if param_idx < len(self._current_summary.params) else f"arg_{param_idx}"
                self._current_summary.internal_sinks.append(
                    SinkReach(
                        param_index=param_idx,
                        param_name=pname,
                        rule_id="SQ-PY-001",
                        category=VulnerabilityCategory.COMMAND_INJECTION,
                        severity=SeverityLevel.CRITICAL,
                        explanation=f"Function parameter '{pname}' reaches command execution sink in {self._current_summary.name}",
                        line=lineno,
                        code_snippet=snippet,
                        file_path=self.file_path,
                    )
                )

        # 3. Dynamic Code Injection sink
        elif call_name in {"eval", "exec"} and call_node.args:
            taint = self._expr_taint_params(call_node.args[0])
            for param_idx in taint:
                pname = self._current_summary.params[param_idx] if param_idx < len(self._current_summary.params) else f"arg_{param_idx}"
                self._current_summary.internal_sinks.append(
                    SinkReach(
                        param_index=param_idx,
                        param_name=pname,
                        rule_id="SQ-PY-009",
                        category=VulnerabilityCategory.CODE_INJECTION,
                        severity=SeverityLevel.CRITICAL,
                        explanation=f"Function parameter '{pname}' reaches dynamic evaluation sink in {self._current_summary.name}",
                        line=lineno,
                        code_snippet=snippet,
                        file_path=self.file_path,
                    )
                )

        # 4. Path Traversal sink
        elif call_name in {"open", "remove", "unlink", "rmtree"} and call_node.args:
            taint = self._expr_taint_params(call_node.args[0])
            for param_idx in taint:
                pname = self._current_summary.params[param_idx] if param_idx < len(self._current_summary.params) else f"arg_{param_idx}"
                self._current_summary.internal_sinks.append(
                    SinkReach(
                        param_index=param_idx,
                        param_name=pname,
                        rule_id="SQ-PY-003",
                        category=VulnerabilityCategory.PATH_TRAVERSAL,
                        severity=SeverityLevel.HIGH,
                        explanation=f"Function parameter '{pname}' reaches filesystem sink in {self._current_summary.name}",
                        line=lineno,
                        code_snippet=snippet,
                        file_path=self.file_path,
                    )
                )

        # 5. SSRF sink
        elif call_name in {"get", "post", "urlopen", "request"} and call_node.args:
            taint = self._expr_taint_params(call_node.args[0])
            for param_idx in taint:
                pname = self._current_summary.params[param_idx] if param_idx < len(self._current_summary.params) else f"arg_{param_idx}"
                self._current_summary.internal_sinks.append(
                    SinkReach(
                        param_index=param_idx,
                        param_name=pname,
                        rule_id="SQ-PY-004",
                        category=VulnerabilityCategory.SSRF,
                        severity=SeverityLevel.HIGH,
                        explanation=f"Function parameter '{pname}' reaches outbound HTTP request sink in {self._current_summary.name}",
                        line=lineno,
                        code_snippet=snippet,
                        file_path=self.file_path,
                    )
                )


class RepositorySymbolTable:
    """Repository-wide index of function summaries and import bindings."""

    def __init__(self) -> None:
        # module_name -> {function_name: FunctionSummary}
        self.modules: dict[str, dict[str, FunctionSummary]] = {}
        # file_path -> {function_name: FunctionSummary}
        self.files: dict[str, dict[str, FunctionSummary]] = {}

    def add_summary(self, summary: FunctionSummary) -> None:
        self.modules.setdefault(summary.module_name, {})[summary.name] = summary
        self.files.setdefault(summary.file_path, {})[summary.name] = summary

    def lookup(
        self,
        current_file: str,
        func_name: str,
        import_map: dict[str, tuple[str, str]],
    ) -> FunctionSummary | None:
        """Resolve a function name against local file, imported symbols, or module paths.

        import_map maps local_alias -> (source_module, original_name)
        """
        normalized_file = current_file.replace("\\", "/")

        # 1. Check self.method call within same file
        if func_name.startswith("self."):
            method_name = func_name[5:]
            if normalized_file in self.files and method_name in self.files[normalized_file]:
                return self.files[normalized_file][method_name]

        # 2. Check local file definition
        if normalized_file in self.files and func_name in self.files[normalized_file]:
            return self.files[normalized_file][func_name]

        # 3. Check direct imported symbol (e.g. from db import query_user)
        if func_name in import_map:
            mod_name, orig_name = import_map[func_name]
            if mod_name in self.modules and orig_name in self.modules[mod_name]:
                return self.modules[mod_name][orig_name]

        # 4. Check qualified module call (e.g. db.query_user)
        if "." in func_name:
            parts = func_name.split(".", 1)
            mod_alias, fn = parts[0], parts[1]
            if mod_alias in import_map:
                mod_name, _ = import_map[mod_alias]
                if mod_name in self.modules and fn in self.modules[mod_name]:
                    return self.modules[mod_name][fn]
            if mod_alias in self.modules and fn in self.modules[mod_alias]:
                return self.modules[mod_alias][fn]

        return None


def index_source_file(file_path: str, source_code: str) -> list[FunctionSummary]:
    """Parse a single Python file and extract all function summaries."""
    try:
        tree = ast.parse(source_code, filename=file_path)
    except (SyntaxError, ValueError):
        return []

    rel_path = file_path.replace("\\", "/")
    # Determine module name from filename (e.g. 'db.py' -> 'db', 'pkg/auth.py' -> 'pkg.auth')
    mod_stem = Path(rel_path).stem
    mod_parts = list(Path(rel_path).parent.parts) + [mod_stem]
    clean_parts = [p for p in mod_parts if p and p != "."]
    mod_name = ".".join(clean_parts) if clean_parts else mod_stem

    lines = source_code.splitlines()
    extractor = FunctionSummaryExtractor(rel_path, mod_name, lines)
    extractor.visit(tree)
    return list(extractor.summaries.values())


def build_repository_symbol_table(repo_root: Path, relative_paths: list[str]) -> RepositorySymbolTable:
    """Build a global symbol table from all Python files in the repository."""
    table = RepositorySymbolTable()

    for rel_path in relative_paths:
        if not rel_path.endswith((".py", ".pyi")):
            continue
        full_path = repo_root / rel_path
        if not full_path.exists() or not full_path.is_file():
            continue
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        summaries = index_source_file(rel_path, content)
        for s in summaries:
            table.add_summary(s)

    return table
