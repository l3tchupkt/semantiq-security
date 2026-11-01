"""Unit tests for evidence-backed external dependency boundary resolution.

Verifies:
1. Manifest parsing across pyproject.toml, setup.cfg, requirements.txt.
2. Sibling directory and site-packages external dependency discovery.
3. Import mapping with provenance tracking (LOCAL_REPOSITORY, EXTERNAL_DEPENDENCY, STANDARD_LIBRARY).
4. Static AST symbol extraction (classes, inheritance hierarchies, methods, line numbers) without code execution.
5. Bounded source slicing with line numbering and limits.
6. Investigation tool and SDK integration (resolve_dependency_symbol, get_dependency_source).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from semantiq.analysis.dependency_resolution import DependencyResolver
from semantiq.client import Semantiq
from semantiq.discovery.investigation_tools import InvestigationToolExecutor
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.repository.intelligence import RepositoryIntelligence


@pytest.fixture
def mock_repo_with_sibling(tmp_path: Path) -> tuple[Path, Path]:
    """Create a temporary repository and a sibling external dependency repository."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Main repository
    repo_root = workspace / "my-service"
    repo_root.mkdir()

    # Create pyproject.toml
    pyproject = repo_root / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "my-service"
version = "1.0.0"
dependencies = [
    "ext-lib>=2.0.0",
    "helper-pkg",
]
""",
        encoding="utf-8",
    )

    # Local files
    local_pkg = repo_root / "my_service"
    local_pkg.mkdir()
    (local_pkg / "__init__.py").write_text("", encoding="utf-8")
    (local_pkg / "app.py").write_text(
        """from ext_lib.plugin import BaseWorker

class CustomWorker(BaseWorker):
    def handle_task(self, task_id: str):
        \"\"\"Handle task implementation.\"\"\"
        return self.execute(task_id)
""",
        encoding="utf-8",
    )

    # Sibling dependency repository
    sibling_root = workspace / "ext-lib"
    sibling_root.mkdir()
    ext_pkg = sibling_root / "ext_lib"
    ext_pkg.mkdir()
    (ext_pkg / "__init__.py").write_text("", encoding="utf-8")
    (ext_pkg / "plugin.py").write_text(
        """# Third-party library plugin
class CoreClient:
    pass

class BaseWorker(CoreClient):
    \"\"\"Base worker provided by external dependency.\"\"\"
    def __init__(self, name: str):
        self.name = name

    def execute(self, task_id: str):
        \"\"\"Execute given task.\"\"\"
        return True
""",
        encoding="utf-8",
    )

    return repo_root, sibling_root


def test_dependency_manifest_parsing(mock_repo_with_sibling: tuple[Path, Path]) -> None:
    repo_root, _ = mock_repo_with_sibling
    resolver = DependencyResolver(repo_root)

    assert "ext-lib" in resolver.declared_dependencies
    assert "helper-pkg" in resolver.declared_dependencies
    assert resolver.declared_dependencies["ext-lib"] == ">=2.0.0"


def test_sibling_repository_discovery(mock_repo_with_sibling: tuple[Path, Path]) -> None:
    repo_root, sibling_root = mock_repo_with_sibling
    resolver = DependencyResolver(repo_root)

    assert "ext-lib" in resolver.dependency_roots
    assert resolver.dependency_roots["ext-lib"] == sibling_root


def test_import_to_source_mapping(mock_repo_with_sibling: tuple[Path, Path]) -> None:
    repo_root, sibling_root = mock_repo_with_sibling
    resolver = DependencyResolver(repo_root)

    # 1. Local repository mapping
    local_p, pkg_name, prov = resolver.map_import_to_source("my_service.app")
    assert local_p is not None
    assert local_p.name == "app.py"
    assert prov == "LOCAL_REPOSITORY"

    # 2. External dependency mapping
    ext_p, ext_pkg, ext_prov = resolver.map_import_to_source("ext_lib.plugin")
    assert ext_p is not None
    assert ext_p == sibling_root / "ext_lib" / "plugin.py"
    assert ext_pkg == "ext-lib"
    assert ext_prov == "EXTERNAL_DEPENDENCY"

    # 3. Standard library mapping
    json_p, _, json_prov = resolver.map_import_to_source("json")
    assert json_p is not None
    assert json_prov in ("STANDARD_LIBRARY", "EXTERNAL_DEPENDENCY")


def test_static_symbol_resolution(mock_repo_with_sibling: tuple[Path, Path]) -> None:
    repo_root, _ = mock_repo_with_sibling
    resolver = DependencyResolver(repo_root)

    # Resolve BaseWorker from external dependency
    sym = resolver.resolve_symbol("ext_lib.plugin.BaseWorker")
    assert sym is not None
    assert sym.symbol_name == "BaseWorker"
    assert sym.symbol_kind == "class"
    assert sym.provenance == "EXTERNAL_DEPENDENCY"
    assert sym.package_name == "ext-lib"
    assert "CoreClient" in sym.base_classes
    method_names = [m["name"] for m in sym.methods]
    assert "__init__" in method_names
    assert "execute" in method_names
    assert sym.docstring == "Base worker provided by external dependency."


def test_bounded_source_slicing(mock_repo_with_sibling: tuple[Path, Path]) -> None:
    repo_root, _ = mock_repo_with_sibling
    resolver = DependencyResolver(repo_root)

    res = resolver.get_source_slice("ext_lib.plugin", start_line=5, end_line=12, max_lines=10)
    assert res["status"] == "success"
    assert res["provenance"] == "EXTERNAL_DEPENDENCY"
    assert res["package_name"] == "ext-lib"
    assert res["start_line"] == 5
    assert "BaseWorker" in res["snippet"]
    assert "   5 | class BaseWorker(CoreClient):" in res["snippet"]


@pytest.mark.anyio
async def test_sdk_and_tool_executor_integration(mock_repo_with_sibling: tuple[Path, Path]) -> None:
    repo_root, _ = mock_repo_with_sibling

    # Test SDK client facade
    client = Semantiq()
    sym_dict = await client.resolve_dependency_symbol(repo_root, "ext_lib.plugin.BaseWorker")
    assert sym_dict is not None
    assert sym_dict["symbol_name"] == "BaseWorker"
    assert sym_dict["provenance"] == "EXTERNAL_DEPENDENCY"

    slice_dict = await client.get_dependency_source(repo_root, "ext_lib.plugin", 1, 10)
    assert slice_dict["status"] == "success"
    assert "BaseWorker" in slice_dict["snippet"]

    # Test InvestigationToolExecutor
    intel = RepositoryIntelligence(repo_root)
    graph = SemanticProgramGraph()
    executor = InvestigationToolExecutor(repo_root, intel, graph)

    exec_sym = executor.execute("resolve_dependency_symbol", {"symbol_path": "ext_lib.plugin.BaseWorker"})
    assert exec_sym["status"] == "success"
    assert exec_sym["symbol"]["symbol_name"] == "BaseWorker"

    exec_src = executor.execute("get_dependency_source", {"symbol_or_path": "ext_lib.plugin", "start_line": 1, "end_line": 10})
    assert exec_src["status"] == "success"
    assert "BaseWorker" in exec_src["snippet"]
