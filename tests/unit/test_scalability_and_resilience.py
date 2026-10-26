"""Scalability, resilience, and edge-case unit test suite for Semantiq Security.

Tests circular imports, deep call graphs, recursive functions, dynamic dispatch,
malformed syntax, ignored directories, and bounded timeout/coverage reporting.
"""

from __future__ import annotations

import time
from pathlib import Path

from semantiq.discovery.engine import VulnerabilityDiscoveryEngine
from semantiq.discovery.orchestrator import InvestigationBudget, InvestigationOrchestrator
from semantiq.models import ValidationStatus, VulnerabilityCategory
from semantiq.repository.intelligence import RepositoryIntelligence


def test_circular_imports_resilience(tmp_path: Path) -> None:
    """Verify that mutually circular imports do not cause recursion errors or infinite loops."""
    mod_a = tmp_path / "mod_a.py"
    mod_b = tmp_path / "mod_b.py"

    mod_a.write_text(
        "import mod_b\n\ndef func_a(x):\n    return mod_b.func_b(x)\n",
        encoding="utf-8",
    )
    mod_b.write_text(
        "import mod_a\n\ndef func_b(y):\n    return mod_a.func_a(y)\n",
        encoding="utf-8",
    )

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["mod_a.py", "mod_b.py"])

    assert len(intel.symbols) == 2
    assert "mod_a.py" in intel.symbols
    assert "mod_b.py" in intel.symbols


def test_deep_call_graph_budget_enforcement(tmp_path: Path) -> None:
    """Verify that deep call chains beyond max_depth are bounded without stack overflow."""
    code_lines = []
    # Generate 15 chained functions: f0 -> f1 -> f2 ... -> f14
    for i in range(14):
        code_lines.append(f"def f_{i}(param):\n    return f_{i+1}(param)\n")
    code_lines.append(
        "import subprocess\ndef f_14(param):\n    subprocess.run(param, shell=True)\n"
    )
    chain_file = tmp_path / "chain.py"
    chain_file.write_text("\n".join(code_lines), encoding="utf-8")

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["chain.py"])

    budget = InvestigationBudget(max_depth=4)
    orchestrator = InvestigationOrchestrator(
        repository_root=tmp_path,
        intelligence=intel,
        budget=budget,
    )

    engine = VulnerabilityDiscoveryEngine(
        repository_root=tmp_path,
        intelligence=intel,
        orchestrator=orchestrator,
    )

    findings = engine.scan_files(["chain.py"])
    assert len(findings) >= 1
    # Call chain should be bounded by max_depth
    ci_finding = next(f for f in findings if f.category == VulnerabilityCategory.COMMAND_INJECTION)
    assert len(ci_finding.attack_chain) <= 6  # Entry + Dispatch + Execution + Impact


def test_recursive_function_exploration(tmp_path: Path) -> None:
    """Verify that self-recursive functions do not trigger infinite loops in call chain traversal."""
    rec_file = tmp_path / "rec.py"
    rec_file.write_text(
        "import os\ndef recurse_rm(path, depth):\n    if depth <= 0:\n        os.remove(path)\n        return\n    recurse_rm(path, depth - 1)\n",
        encoding="utf-8",
    )

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["rec.py"])

    orchestrator = InvestigationOrchestrator(
        repository_root=tmp_path,
        intelligence=intel,
        budget=InvestigationBudget(max_depth=5),
    )

    engine = VulnerabilityDiscoveryEngine(
        repository_root=tmp_path,
        intelligence=intel,
        orchestrator=orchestrator,
    )

    findings = engine.scan_files(["rec.py"])
    assert len(findings) >= 1
    pt_finding = next(f for f in findings if f.category == VulnerabilityCategory.PATH_TRAVERSAL)
    assert pt_finding.validation_status in {ValidationStatus.EVIDENCE_SUPPORTED, ValidationStatus.CANDIDATE}


def test_dynamic_dispatch_unresolved_call_tracking(tmp_path: Path) -> None:
    """Verify that dynamic dispatch (getattr) is tracked as UnresolvedCall and marks status INCONCLUSIVE."""
    dyn_file = tmp_path / "dynamic_service.py"
    dyn_file.write_text(
        """
import subprocess

def dispatch_handler(handler_name, user_cmd):
    # Dynamic dispatch via getattr
    subprocess_helper = getattr(subprocess, handler_name)
    subprocess.run(user_cmd, shell=True)
""",
        encoding="utf-8",
    )

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["dynamic_service.py"])

    assert len(intel.unresolved_calls) >= 1
    unres = intel.unresolved_calls[0]
    assert unres.file_path == "dynamic_service.py"
    assert "getattr" in unres.call_expression or unres.reason == "dynamic_dispatch_or_unresolved_expression"

    orchestrator = InvestigationOrchestrator(
        repository_root=tmp_path,
        intelligence=intel,
    )
    engine = VulnerabilityDiscoveryEngine(
        repository_root=tmp_path,
        intelligence=intel,
        orchestrator=orchestrator,
    )

    findings = engine.scan_files(["dynamic_service.py"])
    assert len(findings) >= 1
    finding = findings[0]
    # Unresolved dispatch should be reflected in uncertainty and status
    assert "traverses dynamic dispatch" in finding.uncertainty.lower()
    assert finding.validation_status == ValidationStatus.INCONCLUSIVE


def test_malformed_syntax_and_partial_coverage(tmp_path: Path) -> None:
    """Verify that unparseable syntax is recorded in failed_parsing_files and coverage gap notes."""
    valid_file = tmp_path / "valid.py"
    valid_file.write_text("def ping():\n    return 'pong'\n", encoding="utf-8")

    broken_file = tmp_path / "broken.py"
    broken_file.write_text("def unparseable( syntax : [ ] { ;;\n", encoding="utf-8")

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["valid.py", "broken.py"])

    assert "broken.py" in intel.failed_parsing_files
    assert "valid.py" not in intel.failed_parsing_files

    cov = intel.compute_coverage(["valid.py", "broken.py"])
    assert cov.parsed_files == 1
    assert len(cov.failed_parsing_files) == 1
    assert cov.coverage_percentage == 50.0
    assert any("could not be parsed as valid AST syntax" in note for note in cov.gap_notes)


def test_large_synthetic_repository_scalability(tmp_path: Path) -> None:
    """Verify performance and caching on a synthetic repository with 30 modules."""
    files: list[str] = []
    for i in range(30):
        fname = f"module_{i:02d}.py"
        fpath = tmp_path / fname
        fpath.write_text(
            f"""
import hashlib

def helper_{i}(val: str) -> str:
    h = hashlib.sha256(val.encode()).hexdigest()
    return f'res_{{h}}'

def runner_{i}(data: str) -> str:
    return helper_{i}(data)
""",
            encoding="utf-8",
        )
        files.append(fname)

    intel = RepositoryIntelligence(tmp_path)

    # First pass: cold cache
    t0 = time.perf_counter()
    intel.index_repository(files)
    cold_dur = time.perf_counter() - t0

    assert len(intel.symbols) == 30
    assert len(intel._content_cache) == 30

    # Second pass: warm cache
    t1 = time.perf_counter()
    intel.index_repository(files)
    warm_dur = time.perf_counter() - t1

    # Warm pass must be faster than cold pass
    assert warm_dur <= cold_dur
    assert len(intel.file_metadata) == 30
