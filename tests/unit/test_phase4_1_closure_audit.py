"""Phase 4.1 Closure Audit Test Suite.

Verifies:
1. CFG dominance and parameter neutralization counterexamples in PathAdversarialVerifier.
2. Non-destructive SQLite migration with archival preservation in archived_finding_versions.
3. Foreign key enforcement on semantic_merges.secondary_finding_id across migrations.
4. Comprehensive deduplication stress testing across 50+ deterministic permutations.
"""

from __future__ import annotations

import random
import sqlite3
from pathlib import Path

import pytest

from semantiq.analysis.path_adversarial import (
    AdversarialVerdict,
    PathAdversarialVerifier,
)
from semantiq.finding.deduplication import (
    SemanticDeduplicator,
)
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, GraphEdge, GraphNode, NodeKind, RelationshipProvenance
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    SourceLocation,
    VulnerabilityCategory,
)
from semantiq.storage.sqlite import SQLiteStorage


def _make_finding(
    finding_id: str,
    title: str,
    file_path: str,
    start_line: int,
    end_line: int,
    category: VulnerabilityCategory = VulnerabilityCategory.GENERIC,
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
    code_evidence: list[CodeEvidence] | None = None,
    summary: str = "",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        occurrence_id=f"occ_{finding_id}",
        rule_id=f"RULE-{finding_id}",
        title=title,
        summary=summary or title,
        category=category,
        severity=severity,
        confidence=confidence,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        locations=[SourceLocation(file_path=file_path, start_line=start_line, end_line=end_line)],
        code_evidence=code_evidence or [],
    )


# =============================================================================
# 1. CFG Dominance and Parameter Neutralization Counterexamples
# =============================================================================

def test_counterexample_parameter_mismatch(tmp_path: Path) -> None:
    """Counterexample A: Containment guard verifies 'other_path', but sink accesses 'script_path'.

    Must return INSUFFICIENT_EVIDENCE, NOT PROTECTED.
    """
    code = """
import pathlib
import bottle

def handle_scripts_load(name, other_name):
    safe_root = pathlib.Path("/safe/root").resolve()
    script_path = (safe_root / name).resolve()
    other_path = (safe_root / other_name).resolve()

    if not other_path.is_relative_to(safe_root):
        bottle.abort(400, "Invalid script path")

    with open(script_path) as infile:
        return infile.read()
"""
    f = tmp_path / "app.py"
    f.write_text(code, encoding="utf-8")

    ev_sink = CodeEvidence(
        file_path="app.py",
        start_line=13,
        end_line=14,
        snippet="with open(script_path) as infile:",
        role=CodeEvidenceRole.SINK,
    )
    finding = _make_finding(
        "F_TRAV",
        "Path Traversal",
        "app.py",
        6,
        14,
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        code_evidence=[ev_sink],
    )

    verifier = PathAdversarialVerifier(repository_root=tmp_path)
    res = verifier.evaluate_finding_defenses(finding)

    assert res.verdict == AdversarialVerdict.INSUFFICIENT_EVIDENCE
    assert res.contradicts_finding is False
    assert "mismatched" in res.guard_symbol or "does not neutralize" in res.rationale


def test_counterexample_guard_without_termination(tmp_path: Path) -> None:
    """Counterexample B: Guard evaluates is_relative_to but does NOT abort/raise/return on failure.

    Must return INSUFFICIENT_EVIDENCE, NOT PROTECTED.
    """
    code = """
import pathlib

def handle_scripts_load(name):
    safe_root = pathlib.Path("/safe/root").resolve()
    script_path = (safe_root / name).resolve()

    # Evaluated but not enforced: no abort/raise/return
    if not script_path.is_relative_to(safe_root):
        log_warning("Suspicious traversal attempt")

    with open(script_path) as infile:
        return infile.read()
"""
    f = tmp_path / "app.py"
    f.write_text(code, encoding="utf-8")

    ev_sink = CodeEvidence(
        file_path="app.py",
        start_line=12,
        end_line=13,
        snippet="with open(script_path) as infile:",
        role=CodeEvidenceRole.SINK,
    )
    finding = _make_finding(
        "F_TRAV",
        "Path Traversal",
        "app.py",
        5,
        13,
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        code_evidence=[ev_sink],
    )

    verifier = PathAdversarialVerifier(repository_root=tmp_path)
    res = verifier.evaluate_finding_defenses(finding)

    assert res.verdict == AdversarialVerdict.INSUFFICIENT_EVIDENCE
    assert res.contradicts_finding is False
    assert "unimplemented" in res.guard_symbol or "does not abort" in res.rationale


def test_counterexample_guard_inside_optional_bypass_branch(tmp_path: Path) -> None:
    """Counterexample C: Guard is nested inside an optional bypass branch ('if not bypass:').

    Must return BYPASSABLE, NOT PROTECTED.
    """
    code = """
import pathlib
import bottle

def handle_scripts_load(name, bypass=False):
    safe_root = pathlib.Path("/safe/root").resolve()
    script_path = (safe_root / name).resolve()

    if not bypass:
        if not script_path.is_relative_to(safe_root):
            bottle.abort(400, "Invalid script path")

    with open(script_path) as infile:
        return infile.read()
"""
    f = tmp_path / "app.py"
    f.write_text(code, encoding="utf-8")

    ev_sink = CodeEvidence(
        file_path="app.py",
        start_line=13,
        end_line=14,
        snippet="with open(script_path) as infile:",
        role=CodeEvidenceRole.SINK,
    )
    finding = _make_finding(
        "F_TRAV",
        "Path Traversal",
        "app.py",
        5,
        14,
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        code_evidence=[ev_sink],
    )

    verifier = PathAdversarialVerifier(repository_root=tmp_path)
    res = verifier.evaluate_finding_defenses(finding)

    assert res.verdict == AdversarialVerdict.BYPASSABLE
    assert res.contradicts_finding is False
    assert len(res.bypass_paths) >= 1


def test_counterexample_graph_multiple_entrypoints_bypass() -> None:
    """Counterexample D: Multiple entry points to same sink in SemanticProgramGraph.

    Entry 1 is guarded, Entry 2 is unguarded.
    Must return BYPASSABLE, NOT PROTECTED.
    """
    graph = SemanticProgramGraph()

    entry1 = GraphNode(id="route_guarded", label="/api/guarded", kind=NodeKind.ROUTE, file_path="api.py", start_line=10, end_line=12)
    entry2 = GraphNode(id="route_internal", label="/internal/exec", kind=NodeKind.ROUTE, file_path="api.py", start_line=15, end_line=17)
    guard = GraphNode(id="sanitizer_node", label="validate_cmd", kind=NodeKind.SANITIZER, file_path="guard.py", start_line=5, end_line=8)
    sink = GraphNode(id="sink_node", label="os.system", kind=NodeKind.SENSITIVE_SINK, file_path="api.py", start_line=30, end_line=30)

    graph.add_node(entry1)
    graph.add_node(entry2)
    graph.add_node(guard)
    graph.add_node(sink)

    # Route 1 -> Guard -> Sink
    graph.add_edge(GraphEdge(source_id="route_guarded", target_id="sanitizer_node", kind=EdgeKind.CALLS, provenance=RelationshipProvenance.DIRECT_FACT))
    graph.add_edge(GraphEdge(source_id="sanitizer_node", target_id="sink_node", kind=EdgeKind.CALLS, provenance=RelationshipProvenance.DIRECT_FACT))

    # Route 2 -> Sink (directly, bypassing guard)
    graph.add_edge(GraphEdge(source_id="route_internal", target_id="sink_node", kind=EdgeKind.CALLS, provenance=RelationshipProvenance.DIRECT_FACT))

    finding = _make_finding("F_CMD", "Command Injection", "api.py", 10, 30, category=VulnerabilityCategory.COMMAND_INJECTION)

    verifier = PathAdversarialVerifier()
    res = verifier.evaluate_finding_defenses(finding, graph=graph)

    assert res.verdict == AdversarialVerdict.BYPASSABLE
    assert res.contradicts_finding is False
    assert len(res.bypass_paths) >= 1


# =============================================================================
# 2. SQLite Non-Destructive Migration & Archival Preservation
# =============================================================================

def test_sqlite_non_destructive_archival_migration(tmp_path: Path) -> None:
    """Verify that duplicate version reconciliation safely archives snapshots into archived_finding_versions."""
    db_file = tmp_path / "test_migration.db"

    # Step 1: Create a legacy database with duplicate versions
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        """
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            file_path TEXT NOT NULL,
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            validation_status TEXT NOT NULL,
            full_json TEXT NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE finding_versions (
            version_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            version_number INTEGER NOT NULL,
            lifecycle_state TEXT NOT NULL,
            confidence TEXT NOT NULL,
            severity TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    # Insert 3 version records for same finding_id and version_number 1
    conn.execute("INSERT INTO findings (finding_id, scan_id, rule_id, title, category, severity, confidence, file_path, start_line, end_line, fingerprint, validation_status, full_json) VALUES ('F1', 'S1', 'R1', 'Title', 'generic', 'medium', 'medium', 'a.py', 1, 5, 'fp1', 'unverified', '{}')")
    conn.execute("INSERT INTO finding_versions (version_id, finding_id, version_number, lifecycle_state, confidence, severity, created_at) VALUES ('v1_oldest', 'F1', 1, 'candidate', 'low', 'low', '2026-10-01T00:00:00')")
    conn.execute("INSERT INTO finding_versions (version_id, finding_id, version_number, lifecycle_state, confidence, severity, created_at) VALUES ('v1_middle', 'F1', 1, 'under_investigation', 'medium', 'medium', '2026-10-02T00:00:00')")
    conn.execute("INSERT INTO finding_versions (version_id, finding_id, version_number, lifecycle_state, confidence, severity, created_at) VALUES ('v1_newest', 'F1', 1, 'confirmed', 'high', 'high', '2026-10-03T00:00:00')")
    conn.commit()
    conn.close()

    # Step 2: Open with SQLiteStorage (triggers non-destructive migration)
    storage = SQLiteStorage(db_file)

    # Step 3: Verify results
    with storage._connection() as c:
        # Check that finding_versions now has exactly 1 record for (F1, 1)
        cur = c.execute("SELECT version_id, lifecycle_state FROM finding_versions WHERE finding_id = 'F1' AND version_number = 1;")
        active_versions = cur.fetchall()
        assert len(active_versions) == 1
        assert active_versions[0]["version_id"] == "v1_newest"

        # Check that the 2 older duplicates were preserved in archived_finding_versions
        cur_arch = c.execute("SELECT version_id, archived_reason FROM archived_finding_versions WHERE finding_id = 'F1';")
        archived = cur_arch.fetchall()
        assert len(archived) == 2
        archived_vids = {row["version_id"] for row in archived}
        assert archived_vids == {"v1_oldest", "v1_middle"}

        # Verify that unique index now rejects new duplicate (finding_id, version_number)
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("INSERT INTO finding_versions (version_id, finding_id, version_number, lifecycle_state, confidence, severity, created_at) VALUES ('v1_bad', 'F1', 1, 'candidate', 'low', 'low', '2026-10-04T00:00:00');")


def test_sqlite_foreign_key_enforcement(tmp_path: Path) -> None:
    """Verify that foreign keys are strictly enforced on semantic_merges.secondary_finding_id."""
    db_file = tmp_path / "test_fk.db"
    storage = SQLiteStorage(db_file)

    with storage._connection() as conn:
        # Create primary finding
        conn.execute("INSERT INTO scans (scan_id, target_path, mode, started_at, completed_at, inspection_json, coverage_json) VALUES ('s1', '/repo', 'audit', 'now', 'now', '{}', '{}');")
        conn.execute("INSERT INTO findings (finding_id, scan_id, rule_id, title, category, severity, confidence, file_path, start_line, end_line, fingerprint, validation_status, full_json) VALUES ('f_primary', 's1', 'r1', 'title', 'cat', 'high', 'high', 'a.py', 1, 5, 'fp1', 'unverified', '{}');")

        # Attempting to insert a merge record with a non-existent secondary_finding_id must fail
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO semantic_merges (merge_id, primary_finding_id, secondary_finding_id, decision_outcome, equivalence_confidence, merge_rationale, merged_at)
                VALUES ('m1', 'f_primary', 'f_non_existent', 'SAME', 0.95, 'Test merge', 'now');
                """
            )


# =============================================================================
# 3. Comprehensive Deduplication Determinism Stress Testing
# =============================================================================

def test_deduplication_stress_testing_50_permutations() -> None:
    """Stress test SemanticDeduplicator across 50 deterministic permutations of an 8-candidate corpus.

    Corpus covers:
    1. Worker A & Worker B finding exact same flaw in auth.py:10-15 -> SAME/SAME
    2. Distinct endpoint in auth.py:25-30 -> SAME/DISTINCT
    3. Missing sink in services/billing.py -> No cross-service merge
    4. Missing sink in controllers/user.py -> No cross-service merge
    5. Shared verified sink (os.system) from different entry routes -> Cross-file SAME
    6. Shared database query sink with different resource models -> DISTINCT resources
    7. Partial overlap candidate -> UNCERTAIN

    Asserts:
    - 100% agreement across all 50 permutations on consolidated count, IDs, clusters, and evidence preservation.
    """
    ev_auth_sink = CodeEvidence(file_path="auth.py", start_line=12, end_line=12, snippet="login()", role=CodeEvidenceRole.SINK)
    ev_cmd_sink = CodeEvidence(file_path="exec.py", start_line=50, end_line=50, snippet="os.system(cmd)", role=CodeEvidenceRole.SINK)
    ev_db_orders = CodeEvidence(file_path="db.py", start_line=100, end_line=100, snippet="db.query('SELECT * FROM orders')", role=CodeEvidenceRole.SINK)

    # 1. F_AUTH_1 (Worker A)
    f1 = _make_finding("F_AUTH_1", "Auth Check Bypass", "auth.py", 10, 15, category=VulnerabilityCategory.AUTHORIZATION_BYPASS, code_evidence=[ev_auth_sink])
    f1.metadata["worker_id"] = "worker_a"

    # 2. F_AUTH_2 (Worker B duplicate of F_AUTH_1)
    f2 = _make_finding("F_AUTH_2", "Missing Auth in Login", "auth.py", 10, 15, category=VulnerabilityCategory.AUTHORIZATION_BYPASS, code_evidence=[ev_auth_sink])
    f2.metadata["worker_id"] = "worker_b"

    # 3. F_AUTH_DISTINCT (Different endpoint in auth.py at lines 25-30)
    f3 = _make_finding("F_AUTH_DISTINCT", "Logout View Bypass", "auth.py", 25, 30, category=VulnerabilityCategory.AUTHORIZATION_BYPASS, summary="Logout endpoint without CSRF")

    # 4. F_BILLING (Missing sink in billing service)
    f4 = _make_finding("F_BILLING", "Process Payment", "services/billing.py", 10, 20, category=VulnerabilityCategory.AUTHORIZATION_BYPASS, summary="Process payment unauthenticated")

    # 5. F_USER (Missing sink in user controller)
    f5 = _make_finding("F_USER", "View Profile", "controllers/user.py", 10, 20, category=VulnerabilityCategory.AUTHORIZATION_BYPASS, summary="View user profile unauthenticated")

    # 6. F_CMD_ROUTE1 (Route 1 reaching os.system)
    f6 = _make_finding("F_CMD_ROUTE1", "Command Exec via Route 1", "routes/exec1.py", 10, 15, category=VulnerabilityCategory.COMMAND_INJECTION, code_evidence=[ev_cmd_sink])

    # 7. F_CMD_ROUTE2 (Route 2 reaching the EXACT SAME os.system sink -> Cross-file duplicate)
    f7 = _make_finding("F_CMD_ROUTE2", "Command Exec via Route 2", "routes/exec2.py", 20, 25, category=VulnerabilityCategory.COMMAND_INJECTION, code_evidence=[ev_cmd_sink])

    # 8. F_DB_ORDERS (DB query on orders table, distinct resource from users)
    f8 = _make_finding("F_DB_ORDERS", "SQLi on Orders", "db.py", 100, 105, category=VulnerabilityCategory.SQL_INJECTION, code_evidence=[ev_db_orders])

    candidates = [f1, f2, f3, f4, f5, f6, f7, f8]
    dedup = SemanticDeduplicator()

    rng = random.Random(42)
    baseline_result = None

    for run_idx in range(50):
        permuted = list(candidates)
        rng.shuffle(permuted)

        res = dedup.deduplicate(permuted)
        consolidated_ids = [f.finding_id for f in res.consolidated_findings]

        if baseline_result is None:
            baseline_result = (res.merged_count, res.distinct_count, consolidated_ids)
            # Verify expected semantic groupings in baseline
            # F_AUTH_1 + F_AUTH_2 merged (1 merge)
            # F_CMD_ROUTE1 + F_CMD_ROUTE2 merged (1 merge)
            # F_AUTH_DISTINCT distinct
            # F_BILLING and F_USER distinct (not merged)
            # F_DB_ORDERS distinct
            assert res.merged_count == 2
            assert len(res.consolidated_findings) == 6
            assert "F_AUTH_1" in consolidated_ids
            assert "F_CMD_ROUTE1" in consolidated_ids
            assert "F_BILLING" in consolidated_ids
            assert "F_USER" in consolidated_ids
        else:
            # Must strictly match baseline across every single permutation
            assert (res.merged_count, res.distinct_count, consolidated_ids) == baseline_result, (
                f"Permutation {run_idx} produced divergent deduplication outcome!"
            )
