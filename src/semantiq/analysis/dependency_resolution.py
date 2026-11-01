"""Evidence-backed external dependency boundary resolution for Python projects.

Enables Semantiq to:
1. Discover declared project dependencies from manifests (pyproject.toml, setup.cfg, requirements.txt).
2. Locate external dependency source files (via sibling workspaces or installed site-packages).
3. Statically parse and resolve classes, inheritance hierarchies, and method definitions across package boundaries.
4. Provide bounded source slices tagged with source provenance (LOCAL_REPOSITORY vs EXTERNAL_DEPENDENCY).
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ResolvedDependencySymbol:
    """A symbol resolved across an external package or dependency boundary."""

    symbol_name: str
    symbol_kind: str  # "class", "function", "method"
    package_name: str
    source_file: str
    line_number: int
    provenance: str  # "EXTERNAL_DEPENDENCY", "LOCAL_REPOSITORY", "STANDARD_LIBRARY"
    base_classes: list[str] = field(default_factory=list)
    methods: list[dict[str, Any]] = field(default_factory=list)
    docstring: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol_name": self.symbol_name,
            "symbol_kind": self.symbol_kind,
            "package_name": self.package_name,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "provenance": self.provenance,
            "base_classes": list(self.base_classes),
            "methods": self.methods,
            "docstring": self.docstring,
        }


class DependencyResolver:
    """Discovers and inspects dependency source trees across package boundaries."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.declared_dependencies: dict[str, str] = {}
        self.dependency_roots: dict[str, Path] = {}
        self._parsed_ast_cache: dict[Path, ast.AST] = {}
        self._discover_dependencies()

    def _discover_dependencies(self) -> None:
        """Parse dependency manifests and locate source trees."""
        # 1. Parse pyproject.toml
        pyproject_p = self.repo_root / "pyproject.toml"
        if pyproject_p.is_file():
            self._parse_pyproject(pyproject_p)

        # 2. Parse setup.cfg / setup.py / requirements.txt
        setup_cfg_p = self.repo_root / "setup.cfg"
        if setup_cfg_p.is_file():
            self._parse_setup_cfg(setup_cfg_p)

        req_p = self.repo_root / "requirements.txt"
        if req_p.is_file():
            self._parse_requirements(req_p)

        # 3. Locate source trees for declared dependencies
        self._locate_source_roots()

    def _parse_pyproject(self, path: Path) -> None:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            parsed: dict[str, Any] = {}
            try:
                import tomllib  # type: ignore[import-not-found,import-untyped]

                parsed = tomllib.loads(content)
            except ImportError:
                try:
                    import tomli  # type: ignore[import-not-found,import-untyped]

                    parsed = tomli.loads(content)
                except ImportError:
                    pass

            if parsed:
                # 1. PEP 621 [project.dependencies]
                project = parsed.get("project", {})
                if isinstance(project, dict):
                    deps = project.get("dependencies", [])
                    if isinstance(deps, list):
                        for dep in deps:
                            if isinstance(dep, str):
                                pkg = re.split(r"[<>=!;~]", dep)[0].strip()
                                ver = dep[len(pkg):].strip() or "*"
                                if pkg:
                                    self.declared_dependencies[pkg] = ver
                    opt_deps = project.get("optional-dependencies", {})
                    if isinstance(opt_deps, dict):
                        for grp_deps in opt_deps.values():
                            if isinstance(grp_deps, list):
                                for dep in grp_deps:
                                    if isinstance(dep, str):
                                        pkg = re.split(r"[<>=!;~]", dep)[0].strip()
                                        ver = dep[len(pkg):].strip() or "*"
                                        if pkg:
                                            self.declared_dependencies[pkg] = ver

                # 2. Poetry [tool.poetry.dependencies]
                poetry = parsed.get("tool", {}).get("poetry", {})
                if isinstance(poetry, dict):
                    p_deps = poetry.get("dependencies", {})
                    if isinstance(p_deps, dict):
                        for pkg, ver in p_deps.items():
                            if pkg.lower() != "python":
                                self.declared_dependencies[pkg] = str(ver)
                    p_dev_deps = poetry.get("dev-dependencies", {})
                    if isinstance(p_dev_deps, dict):
                        for pkg, ver in p_dev_deps.items():
                            self.declared_dependencies[pkg] = str(ver)
                return

            # Fallback line-by-line parsing if no TOML parser is installed
            in_deps_section = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("[") and ("dependencies" in stripped.lower() or "requires" in stripped.lower()):
                    in_deps_section = True
                    continue
                elif stripped.startswith("["):
                    in_deps_section = False
                    continue

                if in_deps_section:
                    if "=" in stripped:
                        pkg_raw, ver_raw = stripped.split("=", 1)
                        pkg = pkg_raw.strip().strip('"').strip("'")
                        ver = ver_raw.strip().strip('"').strip("'")
                        if pkg and not pkg.startswith("#") and pkg.lower() != "python":
                            self.declared_dependencies[pkg] = ver
                    elif stripped.startswith('"') or stripped.startswith("'"):
                        clean = stripped.strip('",\'')
                        pkg = re.split(r"[<>=!;~]", clean)[0].strip()
                        ver = clean[len(pkg):].strip() or "*"
                        if pkg and not pkg.startswith("#"):
                            self.declared_dependencies[pkg] = ver
        except Exception:
            pass

    def _parse_setup_cfg(self, path: Path) -> None:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            in_install_requires = False
            for line in content.splitlines():
                if "install_requires" in line:
                    in_install_requires = True
                    continue
                if in_install_requires:
                    if line.startswith((" ", "\t")):
                        pkg = re.split(r"[<>=!;]", line.strip())[0].strip()
                        if pkg:
                            self.declared_dependencies[pkg] = "*"
                    else:
                        in_install_requires = False
        except Exception:
            pass

    def _parse_requirements(self, path: Path) -> None:
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    pkg = re.split(r"[<>=!;]", clean)[0].strip()
                    if pkg:
                        self.declared_dependencies[pkg] = "*"
        except Exception:
            pass

    def _locate_source_roots(self) -> None:
        """Locate root directory of each declared dependency (sibling workspaces or site-packages)."""
        parent_dir = self.repo_root.parent

        # Sibling checkout search: e.g. for ait-core, look for AIT-Core or ait-core in parent
        for pkg in list(self.declared_dependencies.keys()):
            # Normalize variations: ait-core -> [AIT-Core, ait-core, ait_core]
            candidates = [
                pkg,
                pkg.replace("-", "_"),
                pkg.replace("-", "").lower(),
                "".join(part.capitalize() for part in pkg.split("-")),
                "-".join(part.capitalize() for part in pkg.split("-")),
            ]
            found_dir: Path | None = None
            for cand in candidates:
                cand_path = parent_dir / cand
                if cand_path.is_dir() and cand_path != self.repo_root:
                    found_dir = cand_path
                    break

            if found_dir:
                self.dependency_roots[pkg] = found_dir
                continue

            # Python environment site-packages search
            norm_pkg = pkg.replace("-", "_")
            for sp in sys.path:
                sp_p = Path(sp)
                if sp_p.is_dir():
                    cand_sp = sp_p / norm_pkg
                    if cand_sp.is_dir():
                        self.dependency_roots[pkg] = cand_sp
                        break

    def map_import_to_source(self, import_path: str) -> tuple[Path | None, str, str]:
        """Maps an import statement like 'ait.core.server.plugin' to a concrete file on disk.

        Returns (file_path, package_name, provenance).
        """
        # 1. Check local repository first
        rel_parts = import_path.split(".")
        local_cand = self.repo_root.joinpath(*rel_parts).with_suffix(".py")
        if local_cand.is_file():
            return local_cand, "local", "LOCAL_REPOSITORY"

        # Check local package init
        local_init = self.repo_root.joinpath(*rel_parts) / "__init__.py"
        if local_init.is_file():
            return local_init, "local", "LOCAL_REPOSITORY"

        # 2. Check external dependency roots
        for pkg_name, root in self.dependency_roots.items():
            # Try path directly under root
            cand = root.joinpath(*rel_parts).with_suffix(".py")
            if cand.is_file():
                return cand, pkg_name, "EXTERNAL_DEPENDENCY"
            cand_init = root.joinpath(*rel_parts) / "__init__.py"
            if cand_init.is_file():
                return cand_init, pkg_name, "EXTERNAL_DEPENDENCY"

            # Check if root has a subfolder matching the top-level module (e.g. ait/core/...)
            top_module = rel_parts[0]
            if (root / top_module).is_dir():
                sub_cand = root.joinpath(*rel_parts).with_suffix(".py")
                if sub_cand.is_file():
                    return sub_cand, pkg_name, "EXTERNAL_DEPENDENCY"

        # 3. Check sys.path / standard library
        for sp in sys.path:
            sp_p = Path(sp)
            if sp_p.is_dir():
                cand = sp_p.joinpath(*rel_parts).with_suffix(".py")
                if cand.is_file():
                    prov = "STANDARD_LIBRARY" if ("lib" in str(sp_p).lower() and "site-packages" not in str(sp_p).lower()) else "EXTERNAL_DEPENDENCY"
                    return cand, rel_parts[0], prov
                cand_init = sp_p.joinpath(*rel_parts) / "__init__.py"
                if cand_init.is_file():
                    prov = "STANDARD_LIBRARY" if ("lib" in str(sp_p).lower() and "site-packages" not in str(sp_p).lower()) else "EXTERNAL_DEPENDENCY"
                    return cand_init, rel_parts[0], prov

        # 4. Check importlib.util for standard library
        try:
            import importlib.util

            spec = importlib.util.find_spec(import_path)
            if spec and spec.origin and Path(spec.origin).is_file():
                origin_p = Path(spec.origin)
                prov = "STANDARD_LIBRARY" if "site-packages" not in str(origin_p).lower() else "EXTERNAL_DEPENDENCY"
                return origin_p, rel_parts[0], prov
        except Exception:
            pass

        return None, "", "UNRESOLVED"

    def resolve_symbol(self, symbol_path: str) -> ResolvedDependencySymbol | None:
        """Statically resolve a class or function symbol across module or package boundaries.

        Example: 'ait.core.server.plugin.Plugin' or ('ait.core.server.plugin', 'Plugin')
        """
        parts = symbol_path.split(".")
        if len(parts) < 2:
            return None

        # Try splitting into module path and symbol name
        for i in range(len(parts) - 1, 0, -1):
            mod_path = ".".join(parts[:i])
            sym_name = parts[i]
            file_p, pkg_name, prov = self.map_import_to_source(mod_path)
            if file_p and file_p.is_file():
                res = self._find_symbol_in_file(file_p, sym_name, pkg_name, prov)
                if res:
                    return res

        return None

    def _find_symbol_in_file(
        self,
        file_path: Path,
        target_name: str,
        package_name: str,
        provenance: str,
    ) -> ResolvedDependencySymbol | None:
        """Parse source file with ast and extract target class or function without executing it."""
        try:
            if file_path not in self._parsed_ast_cache:
                code = file_path.read_text(encoding="utf-8", errors="replace")
                self._parsed_ast_cache[file_path] = ast.parse(code, filename=str(file_path))
            tree = self._parsed_ast_cache[file_path]
        except Exception:
            return None

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef) and node.name == target_name:
                base_names = []
                for b in node.bases:
                    if isinstance(b, ast.Name):
                        base_names.append(b.id)
                    elif isinstance(b, ast.Attribute):
                        base_names.append(b.attr)

                methods = []
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        arg_names = [a.arg for a in item.args.args]
                        methods.append({
                            "name": item.name,
                            "line": item.lineno,
                            "args": arg_names,
                            "docstring": ast.get_docstring(item),
                        })

                doc = ast.get_docstring(node)
                return ResolvedDependencySymbol(
                    symbol_name=node.name,
                    symbol_kind="class",
                    package_name=package_name,
                    source_file=str(file_path),
                    line_number=node.lineno,
                    provenance=provenance,
                    base_classes=base_names,
                    methods=methods,
                    docstring=doc,
                )

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target_name:
                doc = ast.get_docstring(node)
                arg_names = [a.arg for a in node.args.args]
                return ResolvedDependencySymbol(
                    symbol_name=node.name,
                    symbol_kind="function",
                    package_name=package_name,
                    source_file=str(file_path),
                    line_number=node.lineno,
                    provenance=provenance,
                    methods=[{"name": node.name, "line": node.lineno, "args": arg_names}],
                    docstring=doc,
                )

        return None

    def get_source_slice(
        self,
        symbol_or_path: str,
        start_line: int,
        end_line: int,
        max_lines: int = 50,
    ) -> dict[str, Any]:
        """Fetch bounded source code lines from a local or external dependency file."""
        # Check if symbol_or_path is a path or an imported module
        file_p: Path | None = None
        pkg_name = "unknown"
        prov = "EXTERNAL_DEPENDENCY"

        target_as_path = Path(symbol_or_path)
        if target_as_path.is_file():
            file_p = target_as_path
            pkg_name = "external"
        else:
            file_p, pkg_name, prov = self.map_import_to_source(symbol_or_path)

        if not file_p or not file_p.is_file():
            return {
                "status": "error",
                "message": f"Source for '{symbol_or_path}' could not be located in local repository or external dependencies.",
                "total_lines": 0,
                "lines": [],
            }

        try:
            all_lines = file_p.read_text(encoding="utf-8", errors="replace").splitlines()
            s_idx = max(0, start_line - 1)
            e_idx = min(len(all_lines), end_line)
            if (e_idx - s_idx) > max_lines:
                e_idx = s_idx + max_lines

            slice_lines = all_lines[s_idx:e_idx]
            numbered = [f"{s_idx + i + 1:4d} | {line_str}" for i, line_str in enumerate(slice_lines)]
            return {
                "status": "success",
                "package_name": pkg_name,
                "file_path": str(file_p),
                "provenance": prov,
                "start_line": s_idx + 1,
                "end_line": e_idx,
                "total_lines": len(all_lines),
                "snippet": "\n".join(numbered),
            }
        except Exception as e:
            return {"status": "error", "message": str(e), "total_lines": 0, "lines": []}
