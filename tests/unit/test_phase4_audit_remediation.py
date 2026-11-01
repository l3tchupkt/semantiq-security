"""Comprehensive regression tests verifying the remediation of all Phase 4 audit findings.

Treats all audit reproduction cases as mandatory regression tests:
- CRITICAL-01: Deduplication order dependency and permutation invariance.
- CRITICAL-02: Fallback sink cross-service over-merging prevention.
- HIGH-01: Graph-backed adversarial path dominance and AST comment isolation.
- HIGH-03: Evidence-grounded severity and confidence elevation bounds.
- MEDIUM-01: Single-file distinct endpoints within 25 lines separation.
- MEDIUM-02: SQLite lifecycle state synchronization with canonical findings.
- MEDIUM-03: Secondary finding persistence, DUPLICATE state, and foreign keys.
- MEDIUM-04: SQLite finding_versions unique constraint on (finding_id, version_number).
- MEDIUM-05: Proof gap reconciliation preserving verified resolutions.
- LOW-01: SARIF directory traversal rejection including percent-encoded sequences.
- LOW-02: SARIF OUTCOME evidence role and proof gap fidelity.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from semantiq.analysis.path_adversarial import (
    AdversarialVerdict,
    GuardReachability,
    PathAdversarialVerifier,
)
from semantiq.finding.deduplication import (
    SemanticDeduplicator,
)
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, GraphEdge, GraphNode, NodeKind, RelationshipProvenance
from semantiq.integrations.sarif import (
    SARIFExporter,
    SARIFImporter,
    normalize_and_validate_sarif_uri,
)
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    Finding,
    FindingLifecycleState,
    ProofGap,
    ProofGapStatus,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.storage.sqlite import SQLiteStorage, StorageError


def _make_finding(
    finding_id: str,
    title: str,
    file_path: str,
    start_line: int,
    end_line: int,
    category: VulnerabilityCategory = VulnerabilityCategory.AUTHORIZATION_BYPASS,
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    code_evidence: list[CodeEvidence] | None = None,
    proof_gaps: list[ProofGap] | None = None,
    summary: str = "",
    rule_id: str = "RULE-001",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        occurrence_id=f"occ_{finding_id}",
        rule_id=rule_id,
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
        proof_gaps=proof_gaps or [],
    )


# -----------------------------------------------------------------------------
# CRITICAL-01: Permutation Invariance in Semantic Deduplication
# -----------------------------------------------------------------------------

def test_audit_critical_01_deduplication_permutation_invariance() -> None:
    """Audit reproduction: 3 findings where F2 and F3 are duplicates in file_b.py, F1 in file_a.py.

    Must produce identical results across all 6 permutations.
    """
    ev1 = [CodeEvidence(file_path="file_a.py", start_line=10, end_line=10, snippet="sink_a()", role=CodeEvidenceRole.SINK, explanation="sink")]
    ev2 = [CodeEvidence(file_path="file_b.py", start_line=50, end_line=50, snippet="sink_b()", role=CodeEvidenceRole.SINK, explanation="sink")]
    ev3 = [CodeEvidence(file_path="file_b.py", start_line=52, end_line=52, snippet="sink_b()", role=CodeEvidenceRole.SINK, explanation="sink")]

    f1 = _make_finding("F1", "Bug 1", "file_a.py", 10, 15, category=VulnerabilityCategory.PATH_TRAVERSAL, code_evidence=ev1)
    f2 = _make_finding("F2", "Bug 2", "file_b.py", 50, 55, category=VulnerabilityCategory.PATH_TRAVERSAL, code_evidence=ev2)
    f3 = _make_finding("F3", "Bug 3", "file_b.py", 52, 57, category=VulnerabilityCategory.PATH_TRAVERSAL, code_evidence=ev3)

    dedup = SemanticDeduplicator()
    candidates = [f1, f2, f3]

    results = []
    for perm in itertools.permutations(candidates):
        res = dedup.deduplicate(list(perm))
        out_ids = [f.finding_id for f in res.consolidated_findings]
        results.append((res.merged_count, out_ids))

    # All 6 permutations must yield identical merge count and consolidated finding IDs
    assert len(results) == 6
    assert all(r == results[0] for r in results)
    assert results[0][0] == 1
    assert results[0][1] == ["F1", "F2"]


# -----------------------------------------------------------------------------
# CRITICAL-02: Fallback Sink Cross-Service Over-Merging Prevention
# -----------------------------------------------------------------------------

def test_audit_critical_02_unknown_sink_cross_file_prevention() -> None:
    """Audit reproduction: Billing in services/billing.py and User in controllers/user.py.

    Neither has an explicit parsed sink snippet. Must NOT be merged across files.
    """
    fb = _make_finding(
        "FB",
        "Billing Payment Capture Bypass",
        "services/billing.py",
        100,
        110,
        category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
        severity=SeverityLevel.CRITICAL,
    )
    fu = _make_finding(
        "FU",
        "User Theme Preference Bypass",
        "controllers/user.py",
        20,
        30,
        category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
        severity=SeverityLevel.LOW,
    )

    dedup = SemanticDeduplicator()
    res = dedup.deduplicate([fb, fu])

    assert res.merged_count == 0
    assert len(res.consolidated_findings) == 2
    assert {f.finding_id for f in res.consolidated_findings} == {"FB", "FU"}


# -----------------------------------------------------------------------------
# MEDIUM-01: Single-File Distinct Endpoints Within 25 Lines Separation
# -----------------------------------------------------------------------------

def test_audit_medium_01_same_file_distinct_endpoints_within_25_lines() -> None:
    """Audit reproduction: /admin/delete_user at line 10 and /admin/view_logs at line 25 in api/admin.py.

    Colocated within 15 lines but represent distinct functions. Must NOT be merged.
    """
    f_del = _make_finding(
        "F_DEL",
        "Delete User Bypass",
        "api/admin.py",
        10,
        15,
        category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
        summary="Unauthenticated user deletion at /admin/delete_user",
    )
    f_log = _make_finding(
        "F_LOG",
        "View Logs Bypass",
        "api/admin.py",
        25,
        30,
        category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
        summary="Unauthenticated log inspection at /admin/view_logs",
    )

    dedup = SemanticDeduplicator()
    res = dedup.deduplicate([f_del, f_log])

    assert res.merged_count == 0
    assert len(res.consolidated_findings) == 2
    assert {f.finding_id for f in res.consolidated_findings} == {"F_DEL", "F_LOG"}


# -----------------------------------------------------------------------------
# HIGH-03: Evidence-Grounded Severity and Confidence Bounds
# -----------------------------------------------------------------------------

def test_audit_high_03_severity_and_confidence_grounding() -> None:
    """Unverified worker cannot unilaterally elevate severity to CRITICAL without verified sink evidence.

    Open critical proof obligations bound confidence to MEDIUM.
    """
    f_info = _make_finding(
        "F_INFO",
        "Missing check in helper",
        "api/auth.py",
        10,
        15,
        severity=SeverityLevel.INFORMATIONAL,
        confidence=ConfidenceLevel.LOW,
    )
    f_info.metadata["worker_id"] = "static_worker"

    f_crit = _make_finding(
        "F_CRIT",
        "Missing check in helper",
        "api/auth.py",
        10,
        15,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
    )
    f_crit.metadata["worker_id"] = "unverified_worker"

    dedup = SemanticDeduplicator()
    res = dedup.deduplicate([f_info, f_crit])

    assert res.merged_count == 1
    merged = res.consolidated_findings[0]
    # Grounded canonical severity remains INFORMATIONAL
    assert merged.severity == SeverityLevel.INFORMATIONAL
    # Unverified escalation preserved as hypothesis in metadata
    assert merged.metadata.get("hypothesized_severity") == "critical"

    # Test confidence bounding with open critical proof gap
    gap_open = ProofGap(
        gap_id="gap_reach",
        description="Verify reachable exploit path from public network",
        target_symbol="check",
        status=ProofGapStatus.OPEN,
    )
    f_gap1 = _make_finding("FG1", "Bug 1", "api/auth.py", 10, 15, confidence=ConfidenceLevel.HIGH, proof_gaps=[gap_open])
    f_gap2 = _make_finding("FG2", "Bug 2", "api/auth.py", 10, 15, confidence=ConfidenceLevel.HIGH, proof_gaps=[gap_open])

    res_gap = dedup.deduplicate([f_gap1, f_gap2])
    assert res_gap.merged_count == 1
    # Bounded to MEDIUM due to open critical proof gap
    assert res_gap.consolidated_findings[0].confidence == ConfidenceLevel.MEDIUM


# -----------------------------------------------------------------------------
# MEDIUM-05: Proof Gap Reconciliation Preserving Verified Resolutions
# -----------------------------------------------------------------------------

def test_audit_medium_05_proof_gap_reconciliation() -> None:
    """When merging findings, a verified resolution supported by evidence must not be lost to an older OPEN copy."""
    gap_open = ProofGap(
        gap_id="gap_reach",
        description="Check network boundary reachability",
        target_symbol="dispatch",
        status=ProofGapStatus.OPEN,
    )
    gap_resolved = ProofGap(
        gap_id="gap_reach",
        description="Check network boundary reachability",
        target_symbol="dispatch",
        status=ProofGapStatus.RESOLVED,
        supporting_evidence=["Verified reachable via live packet capture trace"],
    )

    f_open = _make_finding("F_OPEN", "Bug", "server.py", 10, 15, proof_gaps=[gap_open])
    f_res = _make_finding("F_RES", "Bug", "server.py", 10, 15, proof_gaps=[gap_resolved])

    dedup = SemanticDeduplicator()
    res = dedup.deduplicate([f_open, f_res])

    assert res.merged_count == 1
    merged = res.consolidated_findings[0]
    assert len(merged.proof_gaps) == 1
    assert merged.proof_gaps[0].status == ProofGapStatus.RESOLVED
    assert "Verified reachable via live packet capture trace" in merged.proof_gaps[0].supporting_evidence


# -----------------------------------------------------------------------------
# HIGH-01: Graph-Backed Adversarial Dominance & AST Comment Isolation
# -----------------------------------------------------------------------------

def test_audit_high_01_graph_backed_adversarial_dominance() -> None:
    """SemanticProgramGraph path dominance evaluation:

    - Dominating guard -> PROTECTED (contradicts_finding = True)
    - Bypassable guard with alternate path -> BYPASSABLE (contradicts_finding = False)
    """
    graph = SemanticProgramGraph()

    # Create nodes: entry, sink, guard, bypass
    entry = GraphNode(id="n_entry", label="/api/exec", kind=NodeKind.ROUTE, file_path="api.py", start_line=10, end_line=12)
    sink = GraphNode(id="n_sink", label="os.system", kind=NodeKind.SENSITIVE_SINK, file_path="api.py", start_line=20, end_line=20)
    guard = GraphNode(id="n_guard", label="validate_command", kind=NodeKind.SANITIZER, file_path="guard.py", start_line=5, end_line=8)
    bypass = GraphNode(id="n_bypass", label="raw_dispatch", kind=NodeKind.FUNCTION, file_path="api.py", start_line=15, end_line=18)

    graph.add_node(entry)
    graph.add_node(sink)
    graph.add_node(guard)
    graph.add_node(bypass)

    # Path 1: entry -> guard -> sink (guarded)
    graph.add_edge(GraphEdge(source_id="n_entry", target_id="n_guard", kind=EdgeKind.CALLS, provenance=RelationshipProvenance.DIRECT_FACT))
    graph.add_edge(GraphEdge(source_id="n_guard", target_id="n_sink", kind=EdgeKind.CALLS, provenance=RelationshipProvenance.DIRECT_FACT))

    verifier = PathAdversarialVerifier()
    finding = _make_finding("F_CMD", "Cmd Exec", "api.py", 10, 20, category=VulnerabilityCategory.COMMAND_INJECTION)

    # When guard is the ONLY path to sink: dominates -> PROTECTED
    eval_dom = verifier.evaluate_finding_defenses(finding, graph=graph)
    assert eval_dom.verdict == AdversarialVerdict.PROTECTED
    assert eval_dom.contradicts_finding is True
    assert eval_dom.reachability == GuardReachability.MANDATORY_ON_PATH

    # Add Path 2: entry -> bypass -> sink (unguarded alternate path)
    graph.add_edge(GraphEdge(source_id="n_entry", target_id="n_bypass", kind=EdgeKind.CALLS, provenance=RelationshipProvenance.DIRECT_FACT))
    graph.add_edge(GraphEdge(source_id="n_bypass", target_id="n_sink", kind=EdgeKind.CALLS, provenance=RelationshipProvenance.DIRECT_FACT))

    # Now guard does NOT dominate all paths: bypassable!
    eval_bypass = verifier.evaluate_finding_defenses(finding, graph=graph)
    assert eval_bypass.verdict == AdversarialVerdict.BYPASSABLE
    assert eval_bypass.contradicts_finding is False
    assert len(eval_bypass.bypass_paths) >= 1


def test_audit_high_01_ast_comment_not_treated_as_guard(tmp_path: Path) -> None:
    """Comments mentioning sanitizers must NOT be treated as active defensive guards."""
    src_file = tmp_path / "handler.py"
    src_file.write_text(
        (
            "def handle_download(name):\n"
            "    # is_relative_to was considered but not used here\n"
            "    # bottle.static_file is also not used here\n"
            "    target = open(name).read()\n"
            "    return target\n"
        ),
        encoding="utf-8",
    )

    finding = _make_finding(
        "F_TRAV",
        "Path Traversal",
        "handler.py",
        1,
        5,
        category=VulnerabilityCategory.PATH_TRAVERSAL,
    )

    verifier = PathAdversarialVerifier(repository_root=tmp_path)
    eval_res = verifier.evaluate_finding_defenses(finding)

    # Comments must NOT contradict the finding!
    assert eval_res.contradicts_finding is False
    assert eval_res.verdict != AdversarialVerdict.PROTECTED


# -----------------------------------------------------------------------------
# MEDIUM-02: SQLite Lifecycle State Synchronization
# -----------------------------------------------------------------------------

def test_audit_medium_02_sqlite_lifecycle_state_synchronization(tmp_path: Path) -> None:
    """record_lifecycle_transition must atomically update both transition log and canonical finding state."""
    db_path = tmp_path / "test_lifecycle.db"
    storage = SQLiteStorage(db_path)

    finding = _make_finding("F_SYNC", "State Sync Flaw", "app.py", 10, 15)
    storage.save_finding(finding)

    assert storage.get_finding_by_id("F_SYNC").lifecycle_state == FindingLifecycleState.CANDIDATE

    storage.record_lifecycle_transition(
        transition_id="t_01",
        finding_id="F_SYNC",
        from_state="candidate",
        to_state="confirmed",
        trigger_reason="Multi-perspective verification",
    )

    updated = storage.get_finding_by_id("F_SYNC")
    assert updated.lifecycle_state == FindingLifecycleState.CONFIRMED

    # Test illegal state rejection
    with pytest.raises(ValueError, match="Invalid target lifecycle state"):
        storage.record_lifecycle_transition(
            transition_id="t_02",
            finding_id="F_SYNC",
            from_state="confirmed",
            to_state="non_existent_state",
            trigger_reason="Illegal test",
        )


# -----------------------------------------------------------------------------
# MEDIUM-04: SQLite Finding Versions Unique Constraint
# -----------------------------------------------------------------------------

def test_audit_medium_04_sqlite_version_unique_constraint(tmp_path: Path) -> None:
    """Table finding_versions must enforce uniqueness on (finding_id, version_number)."""
    db_path = tmp_path / "test_versions.db"
    storage = SQLiteStorage(db_path)

    finding = _make_finding("F_VER", "Version Flaw", "app.py", 10, 15)
    storage.save_finding(finding)

    storage.save_finding_version("v1_alpha", "F_VER", 1, "candidate", "low", "low")
    storage.save_finding_version("v1_beta", "F_VER", 1, "candidate", "high", "high")

    versions = storage.get_finding_versions("F_VER")
    # Must replace and maintain exactly 1 version record for version_number 1
    assert len(versions) == 1
    assert versions[0]["confidence"] == "high"


# -----------------------------------------------------------------------------
# MEDIUM-03: SQLite Semantic Merges Foreign Key Integrity
# -----------------------------------------------------------------------------

def test_audit_medium_03_sqlite_semantic_merges_foreign_keys(tmp_path: Path) -> None:
    """semantic_merges must enforce foreign key integrity on both primary and secondary findings."""
    db_path = tmp_path / "test_merges.db"
    storage = SQLiteStorage(db_path)

    primary = _make_finding("F_PRI", "Primary Flaw", "app.py", 10, 15)
    storage.save_finding(primary)

    # Attempt merge with unpersisted secondary finding must fail foreign key constraint
    with pytest.raises(StorageError, match="FOREIGN KEY constraint failed"):
        storage.save_semantic_merge(
            merge_id="m_fail",
            primary_finding_id="F_PRI",
            secondary_finding_id="F_UNSAVED",
            decision_outcome="same",
            equivalence_confidence=0.95,
            merge_rationale="Test failure",
        )

    # When secondary is persisted, merge succeeds and secondary is marked as DUPLICATE
    secondary = _make_finding("F_SEC", "Secondary Flaw", "app.py", 12, 16)
    storage.save_finding(secondary)

    storage.save_semantic_merge(
        merge_id="m_success",
        primary_finding_id="F_PRI",
        secondary_finding_id="F_SEC",
        decision_outcome="same",
        equivalence_confidence=0.95,
        merge_rationale="Identical root cause",
    )

    merges = storage.get_semantic_merges("F_PRI")
    assert len(merges) == 1
    assert merges[0]["secondary_finding_id"] == "F_SEC"

    sec_updated = storage.get_finding_by_id("F_SEC")
    assert sec_updated.lifecycle_state == FindingLifecycleState.DUPLICATE


# -----------------------------------------------------------------------------
# LOW-01: SARIF Directory Traversal Rejection
# -----------------------------------------------------------------------------

def test_audit_low_01_sarif_traversal_rejection() -> None:
    """SARIF importer must reject directory traversal including percent-encoded sequences."""
    with pytest.raises(ValueError, match="Directory traversal detected"):
        normalize_and_validate_sarif_uri("%SRCROOT%/../../../../etc/shadow")

    with pytest.raises(ValueError, match="Directory traversal detected"):
        normalize_and_validate_sarif_uri("file://..%2f..%2f..%2fetc/passwd")

    with pytest.raises(ValueError, match="Directory traversal detected"):
        normalize_and_validate_sarif_uri("subdir/../../../escape.py")

    # Clean relative path must normalize safely
    clean = normalize_and_validate_sarif_uri("%SRCROOT%/ait/gui/server.py")
    assert clean == "ait/gui/server.py"


# -----------------------------------------------------------------------------
# LOW-02: SARIF OUTCOME Role and Proof Gaps Round-Trip Fidelity
# -----------------------------------------------------------------------------

def test_audit_low_02_sarif_outcome_and_proof_gaps_roundtrip() -> None:
    """SARIF export and import must preserve OUTCOME evidence role and structured proof gaps."""
    ev = CodeEvidence(
        file_path="service.py",
        start_line=20,
        end_line=22,
        snippet="subprocess.run(['rm', '-rf', target])",
        role=CodeEvidenceRole.OUTCOME,
        explanation="Destructive outcome execution",
    )
    gap = ProofGap(
        gap_id="gap_fs_perm",
        description="Check filesystem write permissions",
        target_symbol="rm",
        status=ProofGapStatus.RESOLVED,
        supporting_evidence=["Trace verified root daemon invocation"],
    )

    finding = _make_finding(
        "F_OUTCOME",
        "Destructive Command Execution",
        "service.py",
        10,
        22,
        code_evidence=[ev],
        proof_gaps=[gap],
    )

    sarif_str = SARIFExporter.export([finding])
    imported = SARIFImporter.import_sarif(sarif_str)

    assert len(imported) == 1
    imp = imported[0]

    # OUTCOME role preserved
    assert imp.code_evidence[0].role == CodeEvidenceRole.OUTCOME

    # Proof gap preserved
    assert len(imp.proof_gaps) == 1
    assert imp.proof_gaps[0].gap_id == "gap_fs_perm"
    assert imp.proof_gaps[0].status == ProofGapStatus.RESOLVED
    assert "Trace verified root daemon invocation" in imp.proof_gaps[0].supporting_evidence

    # Imported finding is treated as untrusted candidate
    assert imp.lifecycle_state == FindingLifecycleState.CANDIDATE
    assert imp.validation_status == ValidationStatus.INCONCLUSIVE
