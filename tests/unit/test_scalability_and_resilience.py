"""Scalability, resilience, and edge-case unit test suite for Semantiq Security.

Tests circular imports, deep call graphs, recursive functions, dynamic dispatch,
malformed syntax, ignored directories, and bounded timeout/coverage reporting.
"""

from __future__ import annotations

import statistics
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
    """Verify functional caching and performance on a synthetic repository with 30 modules.

    Separates:
      1. Functional cache correctness (zero content reads/reparsing on warm unchanged pass).
      2. Invalidation semantics (changed file is reparsed, unchanged files remain cached).
      3. Call graph / auth boundary non-duplication.
      4. Optimization efficiency (repeated measurements with noise tolerance).
    """
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

    # -------------------------------------------------------------------------
    # Pass 1: Cold Cache (Full read & AST parse)
    # -------------------------------------------------------------------------
    t0 = time.perf_counter()
    intel.index_repository(files)
    cold_dur = time.perf_counter() - t0

    # Functional Cold Assertions
    assert len(intel.symbols) == 30
    assert len(intel._content_cache) == 30
    assert len(intel.file_metadata) == 30
    assert intel.content_reads_count == 30
    assert intel.ast_parsed_count == 30
    assert intel.cached_file_hits_count == 0
    # Each module has 4 calls (encode, sha256, hexdigest, helper_i) -> 30 * 4 = 120
    assert len(intel.call_graph) == 120

    # -------------------------------------------------------------------------
    # Pass 2: Warm Cache (Unchanged files: Zero content reads, Zero AST parse)
    # -------------------------------------------------------------------------
    warm_durations: list[float] = []
    for _ in range(3):
        t_start = time.perf_counter()
        intel.index_repository(files)
        warm_durations.append(time.perf_counter() - t_start)

    # Functional Warm Assertions
    assert intel.content_reads_count == 0, "Unchanged files must avoid unnecessary disk content reads"
    assert intel.ast_parsed_count == 0, "Unchanged files must avoid unnecessary AST reparsing"
    assert intel.cached_file_hits_count == 30, "All 30 unchanged files must be resolved from cache"
    assert len(intel.symbols) == 30
    assert len(intel._content_cache) == 30
    assert len(intel.file_metadata) == 30
    # Crucial correctness guarantee: Call edges must not accumulate duplicate entries on re-index
    assert len(intel.call_graph) == 120

    # -------------------------------------------------------------------------
    # Pass 3: Incremental Invalidation (Modify 1 file)
    # -------------------------------------------------------------------------
    mod_path = tmp_path / "module_00.py"
    mod_path.write_text(
        """
import hashlib

def helper_00(val: str) -> str:
    return "updated_helper"

def new_feature_00(val: str) -> str:
    return "brand_new_symbol"
""",
        encoding="utf-8",
    )

    intel.index_repository(files)

    # Only 1 file modified -> exactly 1 disk read and 1 AST parse; 29 served from cache
    assert intel.content_reads_count == 1, "Only modified file should trigger a content read"
    assert intel.ast_parsed_count == 1, "Only modified file should be reparsed"
    assert intel.cached_file_hits_count == 29, "29 unchanged files must remain served from cache"
    mod_symbols = {s.name for s in intel.symbols["module_00.py"]}
    assert "new_feature_00" in mod_symbols, "Modified file must reflect new AST symbols"
    assert "runner_0" not in mod_symbols, "Removed function must be purged from symbol table"

    # -------------------------------------------------------------------------
    # Pass 4: Performance & Optimization (Noise-Tolerant Multi-Trial Median)
    # -------------------------------------------------------------------------
    warm_median = statistics.median(warm_durations)
    # With 0 disk content reads and 0 AST parsing on warm pass, warm median should
    # comfortably beat cold duration under standard conditions.
    # We apply a 1.25x noise tolerance factor to prevent CI virtualized scheduling spikes
    # from causing false alarms while still verifying caching optimization.
    assert warm_median <= cold_dur * 1.25, (
        f"Warm cache median ({warm_median:.6f}s) exceeded cold time ({cold_dur:.6f}s) with noise tolerance."
    )
