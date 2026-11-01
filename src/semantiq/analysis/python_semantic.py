"""Deep Python semantic navigation, cross-module import resolution, class MRO, and argument mapping."""

from __future__ import annotations

import ast
import contextlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

from semantiq.analysis.dependency_resolution import DependencyResolver
from semantiq.analysis.framework_adapters.registry import GLOBAL_FRAMEWORK_ADAPTER_REGISTRY
from semantiq.graph.interfaces import (
    ArgumentMapping,
    CallRelationship,
    DataflowRelationship,
    FrameworkEntrypoint,
    SourceLocation,
    SymbolIdentity,
)
from semantiq.graph.models import EdgeKind, NodeKind, RelationshipProvenance

logger = logging.getLogger(__name__)


@dataclass
class PythonImport:
    """Imported symbol or module with local alias and relative resolution."""

    source_file: str
    module_name: str
    symbol_name: str  # '*' for wildcard, '' for module import
    local_alias: str
    level: int = 0  # 0 for absolute, 1 for '.', 2 for '..', etc.
    line: int = 1


@dataclass
class PythonCallSite:
    """Detailed AST call site with expression, arguments, and source coordinates."""

    caller_id: str
    caller_qualified_name: str
    call_expression: str
    callee_name: str
    callee_attribute: str | None
    callee_value_expr: str | None
    is_self_call: bool
    is_cls_call: bool
    args: list[str] = field(default_factory=list)
    keywords: dict[str, str] = field(default_factory=dict)
    has_star_args: bool = False
    has_star_kwargs: bool = False
    is_dynamic: bool = False
    dynamic_reason: str | None = None
    line: int = 1
    end_line: int = 1
    col_offset: int = 0
    assigned_to: str | None = None  # Variable receiving return value: res = call(...)


@dataclass
class PythonReturnStatement:
    """Return statement with expression and source line."""

    function_id: str
    return_expression: str
    line: int
    end_line: int


@dataclass
class PythonExceptionStatement:
    """Exception raise or catch block."""

    function_id: str
    exception_type: str
    is_raise: bool
    line: int


@dataclass
class PythonFunction:
    """Function or method definition with parameters, decorators, and callsites."""

    symbol_id: str
    name: str
    qualified_name: str
    module_name: str
    file_path: str
    start_line: int
    end_line: int
    is_async: bool
    is_method: bool
    class_name: str | None
    parameters: list[str] = field(default_factory=list)
    parameter_defaults: dict[str, str] = field(default_factory=dict)
    vararg: str | None = None
    kwarg: str | None = None
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None
    call_sites: list[PythonCallSite] = field(default_factory=list)
    returns: list[PythonReturnStatement] = field(default_factory=list)
    exceptions: list[PythonExceptionStatement] = field(default_factory=list)


@dataclass
class PythonClass:
    """Class definition with base classes, computed MRO, and methods."""

    symbol_id: str
    name: str
    qualified_name: str
    module_name: str
    file_path: str
    start_line: int
    end_line: int
    base_class_names: list[str] = field(default_factory=list)
    resolved_bases: list[str] = field(default_factory=list)  # Qualified names of bases
    mro: list[str] = field(default_factory=list)  # C3 linearized inheritance
    decorators: list[str] = field(default_factory=list)
    methods: dict[str, PythonFunction] = field(default_factory=dict)


@dataclass
class PythonParsedModule:
    """Complete semantic representation of a parsed Python source file."""

    file_path: str
    module_name: str
    tree: ast.AST
    source_lines: list[str]
    imports: list[PythonImport] = field(default_factory=list)
    classes: dict[str, PythonClass] = field(default_factory=dict)
    functions: dict[str, PythonFunction] = field(default_factory=dict)
    module_calls: list[PythonCallSite] = field(default_factory=list)
    all_exports: list[str] = field(default_factory=list)  # __all__ if specified
    entrypoints: list[FrameworkEntrypoint] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


class PythonSemanticEngine:
    """Coordinates deep semantic navigation, cross-module import resolution, and interprocedural analysis."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.dependency_resolver = DependencyResolver(self.repo_root)
        self.modules: dict[str, PythonParsedModule] = {}  # module_name -> module
        self.modules_by_file: dict[str, PythonParsedModule] = {}  # rel_path -> module
        self.symbol_table: dict[str, SymbolIdentity] = {}  # qualified_name -> symbol
        self.call_relationships: list[CallRelationship] = []
        self.dataflow_relationships: list[DataflowRelationship] = []

    def file_path_to_module_name(self, rel_path: str) -> str:
        """Derive standard Python module dotted name from relative file path."""
        p = Path(rel_path.replace("\\", "/"))
        parts = list(p.parent.parts)
        stem = p.stem
        if stem == "__init__":
            return ".".join(parts) if parts else stem
        parts.append(stem)
        return ".".join(parts)

    def parse_source(self, rel_path: str, source_code: str) -> PythonParsedModule:
        """Parse source code into structured Python semantic module."""
        clean_file = rel_path.replace("\\", "/")
        lines = source_code.splitlines()
        mod_name = self.file_path_to_module_name(clean_file)

        try:
            tree = ast.parse(source_code, filename=clean_file)
        except (SyntaxError, ValueError) as err:
            logger.warning("AST parse error in %s: %s", clean_file, err)
            empty_mod = PythonParsedModule(
                file_path=clean_file,
                module_name=mod_name,
                tree=ast.Module(body=[], type_ignores=[]),
                source_lines=lines,
                gaps=[f"Syntax error parsing {clean_file}: {err}"],
            )
            return empty_mod

        parsed = self._extract_module(tree, clean_file, mod_name, lines)
        self.modules[mod_name] = parsed
        self.modules_by_file[clean_file] = parsed
        return parsed

    def _extract_module(
        self,
        tree: ast.AST,
        file_path: str,
        module_name: str,
        source_lines: list[str],
    ) -> PythonParsedModule:
        imports: list[PythonImport] = []
        classes: dict[str, PythonClass] = {}
        functions: dict[str, PythonFunction] = {}
        module_calls: list[PythonCallSite] = []
        all_exports: list[str] = []
        gaps: list[str] = []

        # 1. Framework entrypoint detection across Bottle, Flask, FastAPI, Django, Tornado
        entrypoints = GLOBAL_FRAMEWORK_ADAPTER_REGISTRY.detect_all_entrypoints(
            tree, file_path, source_lines
        )

        # 2. Extract Imports and __all__
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports.append(
                        PythonImport(
                            source_file=file_path,
                            module_name=alias.name,
                            symbol_name="",
                            local_alias=local,
                            level=0,
                            line=node.lineno,
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                level = getattr(node, "level", 0)
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports.append(
                        PythonImport(
                            source_file=file_path,
                            module_name=mod,
                            symbol_name=alias.name,
                            local_alias=local,
                            level=level,
                            line=node.lineno,
                        )
                    )
            elif isinstance(node, ast.Assign):
                # Detect __all__ = ['foo', 'bar']
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "__all__"
                        and isinstance(node.value, (ast.List, ast.Tuple, ast.Set))
                    ):
                            for el in node.value.elts:
                                if isinstance(el, ast.Constant) and isinstance(el.value, str):
                                    all_exports.append(el.value)

        # 3. Walk classes, functions, and statements
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                cls = self._extract_class(node, file_path, module_name, source_lines)
                classes[cls.name] = cls
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = self._extract_function(node, file_path, module_name, None, source_lines)
                functions[fn.name] = fn
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                cs = self._extract_callsite(
                    node.value,
                    caller_id=f"mod:{module_name}",
                    caller_qname=module_name,
                    file_path=file_path,
                    assigned_to=None,
                )
                module_calls.append(cs)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                assigned_target = None
                if node.targets and isinstance(node.targets[0], ast.Name):
                    assigned_target = node.targets[0].id
                cs = self._extract_callsite(
                    node.value,
                    caller_id=f"mod:{module_name}",
                    caller_qname=module_name,
                    file_path=file_path,
                    assigned_to=assigned_target,
                )
                module_calls.append(cs)

        return PythonParsedModule(
            file_path=file_path,
            module_name=module_name,
            tree=tree,
            source_lines=source_lines,
            imports=imports,
            classes=classes,
            functions=functions,
            module_calls=module_calls,
            all_exports=all_exports,
            entrypoints=entrypoints,
            gaps=gaps,
        )

    def _extract_class(
        self,
        node: ast.ClassDef,
        file_path: str,
        module_name: str,
        source_lines: list[str],
    ) -> PythonClass:
        qname = f"{module_name}.{node.name}"
        class_id = f"class:{file_path}:{node.name}"

        bases = [self._format_ast_expr(b) for b in node.bases]
        decorators = [self._format_ast_expr(d) for d in node.decorator_list]

        methods: dict[str, PythonFunction] = {}
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = self._extract_function(
                    item, file_path, module_name, node.name, source_lines
                )
                methods[fn.name] = fn

        return PythonClass(
            symbol_id=class_id,
            name=node.name,
            qualified_name=qname,
            module_name=module_name,
            file_path=file_path,
            start_line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            base_class_names=bases,
            resolved_bases=[],
            mro=[],
            decorators=decorators,
            methods=methods,
        )

    def _extract_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        module_name: str,
        class_name: str | None,
        source_lines: list[str],
    ) -> PythonFunction:
        qname = f"{module_name}.{class_name}.{node.name}" if class_name else f"{module_name}.{node.name}"
        func_id = f"sym:{file_path}:{class_name + '.' + node.name if class_name else node.name}"

        params: list[str] = []
        param_defaults: dict[str, str] = {}
        vararg: str | None = None
        kwarg: str | None = None

        # Positional/Keyword args
        for arg in node.args.args:
            params.append(arg.arg)

        # Map defaults (aligned from right of non-keyword-only args)
        if node.args.defaults:
            offset = len(params) - len(node.args.defaults)
            for idx, default_node in enumerate(node.args.defaults):
                param_idx = offset + idx
                if 0 <= param_idx < len(params):
                    param_defaults[params[param_idx]] = self._format_ast_expr(default_node)

        if node.args.vararg:
            vararg = node.args.vararg.arg
        if node.args.kwarg:
            kwarg = node.args.kwarg.arg

        decorators = [self._format_ast_expr(d) for d in node.decorator_list]
        docstring = ast.get_docstring(node)

        # Collect internal callsites, returns, and exception handling
        call_sites: list[PythonCallSite] = []
        returns: list[PythonReturnStatement] = []
        exceptions: list[PythonExceptionStatement] = []

        class StatementVisitor(ast.NodeVisitor):
            def __init__(self, outer: PythonSemanticEngine) -> None:
                self.outer = outer

            def visit_Call(self, c_node: ast.Call) -> None:
                cs = self.outer._extract_callsite(
                    c_node,
                    caller_id=func_id,
                    caller_qname=qname,
                    file_path=file_path,
                    assigned_to=None,
                )
                call_sites.append(cs)
                self.generic_visit(c_node)

            def visit_Assign(self, a_node: ast.Assign) -> None:
                if isinstance(a_node.value, ast.Call):
                    assigned_target = None
                    if a_node.targets and isinstance(a_node.targets[0], ast.Name):
                        assigned_target = a_node.targets[0].id
                    cs = self.outer._extract_callsite(
                        a_node.value,
                        caller_id=func_id,
                        caller_qname=qname,
                        file_path=file_path,
                        assigned_to=assigned_target,
                    )
                    call_sites.append(cs)
                    # Visit arguments inside the call
                    for arg in a_node.value.args:
                        self.visit(arg)
                    for kw in a_node.value.keywords:
                        self.visit(kw.value)
                    return
                self.generic_visit(a_node)

            def visit_Return(self, r_node: ast.Return) -> None:
                expr = self.outer._format_ast_expr(r_node.value) if r_node.value else "None"
                returns.append(
                    PythonReturnStatement(
                        function_id=func_id,
                        return_expression=expr,
                        line=r_node.lineno,
                        end_line=getattr(r_node, "end_lineno", r_node.lineno),
                    )
                )
                self.generic_visit(r_node)

            def visit_Raise(self, r_node: ast.Raise) -> None:
                exc_expr = self.outer._format_ast_expr(r_node.exc) if r_node.exc else "Exception"
                exceptions.append(
                    PythonExceptionStatement(
                        function_id=func_id,
                        exception_type=exc_expr,
                        is_raise=True,
                        line=r_node.lineno,
                    )
                )
                self.generic_visit(r_node)

        stmt_visitor = StatementVisitor(self)
        for stmt in node.body:
            stmt_visitor.visit(stmt)

        return PythonFunction(
            symbol_id=func_id,
            name=node.name,
            qualified_name=qname,
            module_name=module_name,
            file_path=file_path,
            start_line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            is_async=isinstance(node, ast.AsyncFunctionDef),
            is_method=class_name is not None,
            class_name=class_name,
            parameters=params,
            parameter_defaults=param_defaults,
            vararg=vararg,
            kwarg=kwarg,
            decorators=decorators,
            docstring=docstring,
            call_sites=call_sites,
            returns=returns,
            exceptions=exceptions,
        )

    def _extract_callsite(
        self,
        node: ast.Call,
        caller_id: str,
        caller_qname: str,
        file_path: str,
        assigned_to: str | None = None,
    ) -> PythonCallSite:
        call_expr = self._format_ast_expr(node)
        callee_name = ""
        callee_attr: str | None = None
        callee_val_expr: str | None = None
        is_self = False
        is_cls = False
        is_dynamic = False
        dynamic_reason: str | None = None

        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
            if callee_name in {"getattr", "setattr"}:
                is_dynamic = True
                dynamic_reason = f"Explicit dynamic reflection via {callee_name}()"
        elif isinstance(node.func, ast.Attribute):
            callee_attr = node.func.attr
            callee_name = node.func.attr
            callee_val_expr = self._format_ast_expr(node.func.value)
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "self":
                    is_self = True
                elif node.func.value.id == "cls":
                    is_cls = True
        elif isinstance(node.func, ast.Call):
            is_dynamic = True
            dynamic_reason = "Call on returned callable expression"
            callee_name = "<callable>"
        elif isinstance(node.func, ast.Subscript):
            is_dynamic = True
            dynamic_reason = "Dynamic lookup in dictionary/index"
            callee_name = "<subscript_dispatch>"
        else:
            is_dynamic = True
            dynamic_reason = "Dynamic dispatch expression"
            callee_name = "<dynamic>"

        # Extract arguments
        args = [self._format_ast_expr(a) for a in node.args]
        keywords = {kw.arg: self._format_ast_expr(kw.value) for kw in node.keywords if kw.arg}

        has_star_args = any(isinstance(a, ast.Starred) for a in node.args)
        has_star_kwargs = any(kw.arg is None for kw in node.keywords)

        return PythonCallSite(
            caller_id=caller_id,
            caller_qualified_name=caller_qname,
            call_expression=call_expr,
            callee_name=callee_name,
            callee_attribute=callee_attr,
            callee_value_expr=callee_val_expr,
            is_self_call=is_self,
            is_cls_call=is_cls,
            args=args,
            keywords=keywords,
            has_star_args=has_star_args,
            has_star_kwargs=has_star_kwargs,
            is_dynamic=is_dynamic,
            dynamic_reason=dynamic_reason,
            line=getattr(node, "lineno", 1),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
            col_offset=getattr(node, "col_offset", 0),
            assigned_to=assigned_to,
        )

    def _format_ast_expr(self, expr: ast.AST | None) -> str:
        if expr is None:
            return ""
        if hasattr(ast, "unparse"):
            with contextlib.suppress(Exception):
                return ast.unparse(expr)
        if isinstance(expr, ast.Name):
            return expr.id
        elif isinstance(expr, ast.Attribute):
            return f"{self._format_ast_expr(expr.value)}.{expr.attr}"
        elif isinstance(expr, ast.Constant):
            return repr(expr.value)
        return ""

    # =========================================================================
    # Phase 2 Interprocedural Linking & Resolution
    # =========================================================================

    def link_project(self) -> None:
        """Resolve imports, class inheritance (MRO), interprocedural calls, and argument bindings."""
        # 1. Resolve Class Inheritance and compute MRO
        self._compute_class_hierarchies()

        # 2. Build global Symbol Table
        self._build_symbol_table()

        # 3. Resolve Callsites across files and dependencies
        self._resolve_all_callsites()

    def _compute_class_hierarchies(self) -> None:
        """Compute base class links and C3 MRO linearization for all indexed classes."""
        # Map short class name and qualified class name to PythonClass
        class_map: dict[str, PythonClass] = {}
        for mod in self.modules.values():
            for cls in mod.classes.values():
                class_map[cls.qualified_name] = cls
                class_map[cls.name] = cls

        for mod in self.modules.values():
            for cls in mod.classes.values():
                resolved_bases: list[str] = []
                for base_expr in cls.base_class_names:
                    # Try local module
                    local_qname = f"{mod.module_name}.{base_expr}"
                    if local_qname in class_map:
                        resolved_bases.append(local_qname)
                        continue

                    # Try imports in this module
                    resolved_from_import = self._resolve_import_symbol(mod, base_expr)
                    if resolved_from_import and resolved_from_import in class_map:
                        resolved_bases.append(resolved_from_import)
                        continue

                    # Try external dependency resolution (e.g. ait.core.server.plugin.Plugin)
                    dep_sym = self.dependency_resolver.resolve_symbol(base_expr)
                    if dep_sym:
                        resolved_bases.append(f"{dep_sym.package_name}:{dep_sym.symbol_name}")
                        continue

                    resolved_bases.append(base_expr)

                cls.resolved_bases = resolved_bases

                # Compute simplified C3 MRO
                mro = [cls.qualified_name]
                visited: set[str] = {cls.qualified_name}
                queue = list(resolved_bases)
                while queue:
                    curr_base = queue.pop(0)
                    if curr_base not in visited:
                        visited.add(curr_base)
                        mro.append(curr_base)
                        base_cls = class_map.get(curr_base)
                        if base_cls:
                            queue.extend(base_cls.resolved_bases)

                cls.mro = mro

    def _resolve_import_symbol(self, current_mod: PythonParsedModule, symbol_or_name: str) -> str | None:
        """Resolve a symbol name or alias in the context of current module imports."""
        for imp in current_mod.imports:
            if imp.local_alias == symbol_or_name:
                if imp.level > 0:
                    # Relative import: level 1 is enclosing package (strip 1 part), level 2 is parent, etc.
                    base_parts = current_mod.module_name.split(".")
                    if imp.level <= len(base_parts):
                        rel_pkg = ".".join(base_parts[: len(base_parts) - imp.level])
                        target_mod = f"{rel_pkg}.{imp.module_name}" if imp.module_name else rel_pkg
                    else:
                        target_mod = imp.module_name
                else:
                    target_mod = imp.module_name

                if imp.symbol_name:
                    return f"{target_mod}.{imp.symbol_name}"
                return target_mod

            # Star import check
            if imp.symbol_name == "*":
                target_mod = imp.module_name
                if target_mod in self.modules:
                    target_obj = self.modules[target_mod]
                    if symbol_or_name in target_obj.functions or symbol_or_name in target_obj.classes:
                        return f"{target_mod}.{symbol_or_name}"

        return None

    def _build_symbol_table(self) -> None:
        """Construct universal SymbolIdentity table for all functions, methods, classes, and entrypoints."""
        self.symbol_table.clear()

        for mod in self.modules.values():
            for cls in mod.classes.values():
                loc = SourceLocation(
                    file_path=cls.file_path,
                    start_line=cls.start_line,
                    end_line=cls.end_line,
                )
                self.symbol_table[cls.qualified_name] = SymbolIdentity(
                    symbol_id=cls.symbol_id,
                    name=cls.name,
                    qualified_name=cls.qualified_name,
                    kind=NodeKind.CLASS,
                    location=loc,
                    language="python",
                    is_exported=True,
                    container_symbol=mod.module_name,
                    decorators=cls.decorators,
                    base_classes=cls.base_class_names,
                    mro=cls.mro,
                    provenance=RelationshipProvenance.DIRECT_FACT,
                )

                for method in cls.methods.values():
                    m_loc = SourceLocation(
                        file_path=method.file_path,
                        start_line=method.start_line,
                        end_line=method.end_line,
                    )
                    self.symbol_table[method.qualified_name] = SymbolIdentity(
                        symbol_id=method.symbol_id,
                        name=method.name,
                        qualified_name=method.qualified_name,
                        kind=NodeKind.METHOD,
                        location=m_loc,
                        language="python",
                        is_exported=not method.name.startswith("_") or method.name.startswith("__"),
                        container_symbol=cls.qualified_name,
                        parameters=method.parameters,
                        parameter_defaults=method.parameter_defaults,
                        decorators=method.decorators,
                        docstring=method.docstring,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )

            for fn in mod.functions.values():
                fn_loc = SourceLocation(
                    file_path=fn.file_path,
                    start_line=fn.start_line,
                    end_line=fn.end_line,
                )
                self.symbol_table[fn.qualified_name] = SymbolIdentity(
                    symbol_id=fn.symbol_id,
                    name=fn.name,
                    qualified_name=fn.qualified_name,
                    kind=NodeKind.FUNCTION,
                    location=fn_loc,
                    language="python",
                    is_exported=not fn.name.startswith("_"),
                    container_symbol=mod.module_name,
                    parameters=fn.parameters,
                    parameter_defaults=fn.parameter_defaults,
                    decorators=fn.decorators,
                    docstring=fn.docstring,
                    provenance=RelationshipProvenance.DIRECT_FACT,
                )

    def _resolve_all_callsites(self) -> None:
        """Resolve all call sites to target symbols, construct argument mappings and dataflow links."""
        self.call_relationships.clear()
        self.dataflow_relationships.clear()

        # Index functions and methods by short name and qualified name for fast lookup
        functions_by_name: dict[str, list[PythonFunction]] = {}
        for mod in self.modules.values():
            for fn in mod.functions.values():
                functions_by_name.setdefault(fn.name, []).append(fn)
            for cls in mod.classes.values():
                for m in cls.methods.values():
                    functions_by_name.setdefault(m.name, []).append(m)

        for mod in self.modules.values():
            all_call_sites: list[tuple[PythonCallSite, PythonFunction | None]] = []

            for fn in mod.functions.values():
                for cs in fn.call_sites:
                    all_call_sites.append((cs, fn))

            for cls in mod.classes.values():
                for m in cls.methods.values():
                    for cs in m.call_sites:
                        all_call_sites.append((cs, m))

            for cs in mod.module_calls:
                all_call_sites.append((cs, None))

            for cs, caller_fn in all_call_sites:
                self._resolve_single_callsite(mod, cs, caller_fn, functions_by_name)

    def _resolve_single_callsite(
        self,
        current_mod: PythonParsedModule,
        cs: PythonCallSite,
        caller_fn: PythonFunction | None,
        functions_by_name: dict[str, list[PythonFunction]],
    ) -> None:
        target_fn: PythonFunction | None = None
        target_id: str = f"sym:{cs.callee_name}"
        target_qname: str = cs.callee_name
        provenance = RelationshipProvenance.STATICALLY_RESOLVED
        confidence = 1.0
        is_dynamic = cs.is_dynamic
        dynamic_reason = cs.dynamic_reason

        # 1. Dynamic Dispatch (getattr, dynamic dispatch)
        if cs.is_dynamic:
            provenance = RelationshipProvenance.UNRESOLVED
            confidence = 0.3
            self._record_call(cs, target_id, target_qname, [], is_dynamic=True, dynamic_reason=dynamic_reason, provenance=provenance, confidence=confidence)
            return

        # 2. Self / Cls method call within Class or MRO
        if cs.is_self_call and caller_fn and caller_fn.class_name:
            cls = current_mod.classes.get(caller_fn.class_name)
            if cls:
                # Check current class methods
                if cs.callee_name in cls.methods:
                    target_fn = cls.methods[cs.callee_name]
                else:
                    # Search MRO
                    for base_qname in cls.mro:
                        base_short = base_qname.split(".")[-1]
                        for m_cand in self.modules.values():
                            if base_short in m_cand.classes and cs.callee_name in m_cand.classes[base_short].methods:
                                target_fn = m_cand.classes[base_short].methods[cs.callee_name]
                                break
                        if target_fn:
                            break

                if target_fn:
                    target_id = target_fn.symbol_id
                    target_qname = target_fn.qualified_name
                    confidence = 1.0

        # 3. Method call on variable or instantiated object (e.g. obj.method())
        elif cs.callee_attribute and cs.callee_value_expr:
            val_expr = cs.callee_value_expr
            # Check if val_expr is an imported module name or alias
            resolved_mod_name = self._resolve_import_symbol(current_mod, val_expr)
            if resolved_mod_name and resolved_mod_name in self.modules:
                target_mod = self.modules[resolved_mod_name]
                if cs.callee_attribute in target_mod.functions:
                    target_fn = target_mod.functions[cs.callee_attribute]
                    target_id = target_fn.symbol_id
                    target_qname = target_fn.qualified_name
                    confidence = 0.95

            # Check if val_expr matches an imported class name
            if not target_fn and resolved_mod_name:
                parts = resolved_mod_name.rsplit(".", 1)
                if len(parts) == 2:
                    mod_p, cls_p = parts
                    if mod_p in self.modules and cls_p in self.modules[mod_p].classes:
                        cls_obj = self.modules[mod_p].classes[cls_p]
                        if cs.callee_attribute in cls_obj.methods:
                            target_fn = cls_obj.methods[cs.callee_attribute]
                            target_id = target_fn.symbol_id
                            target_qname = target_fn.qualified_name
                            confidence = 0.95

            # Check external dependency resolver (e.g. ait.core.server.plugin)
            if not target_fn:
                dep_sym = self.dependency_resolver.resolve_symbol(f"{val_expr}.{cs.callee_attribute}")
                if dep_sym:
                    target_id = f"ext:{dep_sym.package_name}:{dep_sym.symbol_name}"
                    target_qname = f"{dep_sym.package_name}.{dep_sym.symbol_name}"
                    provenance = RelationshipProvenance.FRAMEWORK_RESOLVED if "plugin" in val_expr or "server" in val_expr else RelationshipProvenance.STATICALLY_INFERRED
                    confidence = 0.9
                    self._record_call(cs, target_id, target_qname, [], is_dynamic=False, dynamic_reason=None, provenance=provenance, confidence=confidence)
                    return

        # 4. Direct function call: resolve in local module first
        if not target_fn and not cs.callee_attribute:
            if cs.callee_name in current_mod.functions:
                target_fn = current_mod.functions[cs.callee_name]
                target_id = target_fn.symbol_id
                target_qname = target_fn.qualified_name
                confidence = 1.0

            # Then check imported symbols
            if not target_fn:
                resolved_import = self._resolve_import_symbol(current_mod, cs.callee_name)
                if resolved_import:
                    mod_part, sym_part = resolved_import.rsplit(".", 1) if "." in resolved_import else (resolved_import, "")
                    if mod_part in self.modules:
                        target_mod = self.modules[mod_part]
                        if sym_part and sym_part in target_mod.functions:
                            target_fn = target_mod.functions[sym_part]
                        elif sym_part and sym_part in target_mod.classes:
                            # Class instantiation
                            cls_target = target_mod.classes[sym_part]
                            target_id = cls_target.symbol_id
                            target_qname = cls_target.qualified_name
                            confidence = 0.95
                        elif not sym_part and cs.callee_name in target_mod.functions:
                            target_fn = target_mod.functions[cs.callee_name]

                    if target_fn:
                        target_id = target_fn.symbol_id
                        target_qname = target_fn.qualified_name
                        confidence = 0.95

            # Check external dependency resolver
            if not target_fn:
                dep_sym = self.dependency_resolver.resolve_symbol(cs.callee_name)
                if dep_sym:
                    target_id = f"ext:{dep_sym.package_name}:{dep_sym.symbol_name}"
                    target_qname = f"{dep_sym.package_name}.{dep_sym.symbol_name}"
                    provenance = RelationshipProvenance.STATICALLY_INFERRED
                    confidence = 0.85
                    self._record_call(cs, target_id, target_qname, [], is_dynamic=False, dynamic_reason=None, provenance=provenance, confidence=confidence)
                    return

        # 5. Fallback: single unique candidate across repository
        if not target_fn:
            candidates = functions_by_name.get(cs.callee_name, [])
            if len(candidates) == 1:
                target_fn = candidates[0]
                target_id = target_fn.symbol_id
                target_qname = target_fn.qualified_name
                provenance = RelationshipProvenance.PROBABLE
                confidence = 0.65
            elif len(candidates) > 1:
                provenance = RelationshipProvenance.UNRESOLVED
                confidence = 0.3
                is_dynamic = True
                dynamic_reason = f"Ambiguous symbol: {len(candidates)} candidates for '{cs.callee_name}'"

        # Construct argument mappings if target function is resolved
        arg_mappings: list[ArgumentMapping] = []
        if target_fn:
            callee_params = target_fn.parameters
            # If callee is method and caller is self.method(), self is implicit
            usable_params = callee_params[1:] if (target_fn.is_method and callee_params and callee_params[0] in {"self", "cls"}) else callee_params

            for idx, arg_expr in enumerate(cs.args):
                p_name = usable_params[idx] if idx < len(usable_params) else None
                p_idx = idx if idx < len(usable_params) else None
                arg_mappings.append(
                    ArgumentMapping(
                        arg_index=idx,
                        arg_name=None,
                        arg_expression=arg_expr,
                        param_name=p_name,
                        param_index=p_idx,
                        is_variadic=cs.has_star_args,
                        is_keyword=False,
                    )
                )

            for kw_name, kw_expr in cs.keywords.items():
                p_idx = usable_params.index(kw_name) if kw_name in usable_params else None
                arg_mappings.append(
                    ArgumentMapping(
                        arg_index=-1,
                        arg_name=kw_name,
                        arg_expression=kw_expr,
                        param_name=kw_name,
                        param_index=p_idx,
                        is_variadic=cs.has_star_kwargs,
                        is_keyword=True,
                    )
                )

            # Record Return Value Dataflow if assigned: res = callee(...)
            if cs.assigned_to and target_fn.returns:
                for ret in target_fn.returns:
                    self.dataflow_relationships.append(
                        DataflowRelationship(
                            source_id=ret.function_id,
                            source_label=f"return {ret.return_expression}",
                            source_location=SourceLocation(
                                file_path=target_fn.file_path,
                                start_line=ret.line,
                                end_line=ret.end_line,
                            ),
                            target_id=f"var:{current_mod.file_path}:{cs.assigned_to}:{cs.line}",
                            target_label=cs.assigned_to,
                            target_location=SourceLocation(
                                file_path=current_mod.file_path,
                                start_line=cs.line,
                                end_line=cs.end_line,
                            ),
                            edge_kind=EdgeKind.RETURNS_TO,
                            transformation=None,
                            provenance=provenance,
                            confidence=confidence,
                        )
                    )

        self._record_call(
            cs,
            target_id,
            target_qname,
            arg_mappings,
            is_dynamic=is_dynamic,
            dynamic_reason=dynamic_reason,
            provenance=provenance,
            confidence=confidence,
        )

    def _record_call(
        self,
        cs: PythonCallSite,
        callee_id: str,
        callee_name: str,
        arg_mappings: list[ArgumentMapping],
        is_dynamic: bool,
        dynamic_reason: str | None,
        provenance: RelationshipProvenance,
        confidence: float,
    ) -> None:
        call_rel = CallRelationship(
            caller_id=cs.caller_id,
            caller_symbol=cs.caller_qualified_name,
            callee_id=callee_id,
            callee_name=callee_name,
            call_site=SourceLocation(
                file_path=cs.caller_id.split(":")[1] if ":" in cs.caller_id else "",
                start_line=cs.line,
                end_line=cs.end_line,
                start_col=cs.col_offset,
            ),
            call_expression=cs.call_expression,
            argument_mappings=arg_mappings,
            is_dynamic=is_dynamic,
            dynamic_reason=dynamic_reason,
            provenance=provenance,
            confidence=confidence,
        )
        self.call_relationships.append(call_rel)

    # =========================================================================
    # Public Query Interfaces
    # =========================================================================

    def resolve_symbol_detail(self, symbol_or_qname: str) -> SymbolIdentity | None:
        """Resolve a symbol or qualified name with complete MRO, parameters, and location."""
        # Exact match
        if symbol_or_qname in self.symbol_table:
            return self.symbol_table[symbol_or_qname]

        # Match by short name or partial suffix
        candidates = [
            sym for qname, sym in self.symbol_table.items()
            if qname.endswith(f".{symbol_or_qname}") or sym.name == symbol_or_qname
        ]
        if len(candidates) == 1:
            return candidates[0]

        # Check external dependency resolver
        dep_sym = self.dependency_resolver.resolve_symbol(symbol_or_qname)
        if dep_sym:
            loc = SourceLocation(
                file_path=dep_sym.source_file,
                start_line=dep_sym.line_number,
                end_line=dep_sym.line_number,
            )
            return SymbolIdentity(
                symbol_id=f"ext:{dep_sym.package_name}:{dep_sym.symbol_name}",
                name=dep_sym.symbol_name,
                qualified_name=f"{dep_sym.package_name}.{dep_sym.symbol_name}",
                kind=NodeKind.CLASS if dep_sym.symbol_kind == "class" else NodeKind.FUNCTION,
                location=loc,
                language="python",
                is_exported=True,
                container_symbol=dep_sym.package_name,
                base_classes=dep_sym.base_classes,
                mro=dep_sym.base_classes,
                docstring=dep_sym.docstring,
                provenance=RelationshipProvenance.FRAMEWORK_RESOLVED if dep_sym.provenance == "EXTERNAL_DEPENDENCY" else RelationshipProvenance.STATICALLY_RESOLVED,
            )

        return None

    def get_callers(self, symbol_qname: str) -> list[CallRelationship]:
        """Find all call relationships that target the specified symbol."""
        results: list[CallRelationship] = []
        for call in self.call_relationships:
            if call.callee_name == symbol_qname or call.callee_id.endswith(f":{symbol_qname}") or "." in call.callee_name and call.callee_name.split(".")[-1] == symbol_qname:
                results.append(call)
        return results

    def get_callees(self, caller_qname: str) -> list[CallRelationship]:
        """Find all outgoing call relationships from the specified caller."""
        results: list[CallRelationship] = []
        for call in self.call_relationships:
            if call.caller_symbol == caller_qname or call.caller_id.endswith(f":{caller_qname}") or "." in call.caller_symbol and call.caller_symbol.split(".")[-1] == caller_qname:
                results.append(call)
        return results

    def get_all_entrypoints(self) -> list[FrameworkEntrypoint]:
        """Retrieve all framework entrypoints detected across all modules."""
        entrypoints: list[FrameworkEntrypoint] = []
        for mod in self.modules.values():
            entrypoints.extend(mod.entrypoints)
        return entrypoints

    def get_unresolved_dispatches(self) -> list[CallRelationship]:
        """Retrieve all call sites involving dynamic dispatch or unresolved targets."""
        return [c for c in self.call_relationships if c.is_dynamic or c.provenance == RelationshipProvenance.UNRESOLVED]
