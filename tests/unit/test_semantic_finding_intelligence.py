"""Comprehensive unit tests for Semantic Finding Intelligence, Deduplication, Workbench (V5), and SARIF interoperability."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from semantiq.analysis.path_adversarial import (
    GuardEffectiveness,
    GuardReachability,
    PathAdversarialVerifier,
)
from semantiq.finding.deduplication import (
    EquivalenceOutcome,
    SemanticDeduplicator,
)
from semantiq.finding.identity import (
    AttackerCapability,
    RootCauseFamily,
    SecurityInvariant,
    SemanticFindingIdentity,
)
from semantiq.integrations.sarif import SARIFExporter, SARIFImporter
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    EvidenceProvenance,
    EvidenceVerificationStatus,
    Finding,
    FindingLifecycleState,
    ProofGap,
    ProofGapStatus,
    SeverityLevel,
    SourceLocation,
    VulnerabilityCategory,
)
from semantiq.storage.sqlite import SCHEMA_V2, SQLiteStorage


def _make_dummy_finding(
    finding_id: str,
    title: str,
    file_path: str,
    start_line: int,
    category: VulnerabilityCategory = VulnerabilityCategory.AUTHORIZATION_BYPASS,
    code_evidence: list[CodeEvidence] | None = None,
    proof_gaps: list[ProofGap] | None = None,
    contributing_worker: str = "worker_1",
    rule_id: str = "SEM-AUTH-001",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        occurrence_id=f"occ_{finding_id}",
        rule_id=rule_id,
        title=title,
        summary=f"Summary for {title}",
        category=category,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line + 5,
        locations=[SourceLocation(file_path=file_path, start_line=start_line, end_line=start_line + 5)],
        code_evidence=code_evidence or [],
        proof_gaps=proof_gaps or [],
        metadata={"contributing_worker": contributing_worker},
    )


# =========================================================================
# 1. Semantic Finding Identity & Structural Hashing Tests
# =========================================================================

def test_semantic_finding_identity_determinism_and_hashing() -> None:
    """Semantic finding identity produces deterministic hashes independent of file, line, or finding ID."""
    identity1 = SemanticFindingIdentity(
        root_cause_family=RootCauseFamily.MISSING_AUTHENTICATION,
        security_invariant=SecurityInvariant.AUTH_ENFORCEMENT,
        entry_point="POST /cmd",
        sensitive_sink="dispatch_command",
        dataflow_summary="unauthenticated request dispatches privileged command",
        required_capability=AttackerCapability.NETWORK_UNAUTHENTICATED,
        prerequisites=["network access to port 8080"],
        known_mitigations=["enforce session token check"],
    )

    identity2 = SemanticFindingIdentity(
        root_cause_family=RootCauseFamily.MISSING_AUTHENTICATION,
        security_invariant=SecurityInvariant.AUTH_ENFORCEMENT,
        entry_point="POST /cmd",
        sensitive_sink="dispatch_command",
        dataflow_summary="different wording but same semantics",
        required_capability=AttackerCapability.NETWORK_UNAUTHENTICATED,
        prerequisites=["network access to port 8080"],
        known_mitigations=["enforce session token check"],
    )

    # Identical root cause, invariant, sink, and capability must have same structural hash
    assert identity1.structural_hash == identity2.structural_hash
    assert len(identity1.structural_hash) == 16
    assert len(identity1.semantic_fingerprint) == 24

    # Distinct root cause or security invariant must produce different structural hashes
    identity_distinct = SemanticFindingIdentity(
        root_cause_family=RootCauseFamily.CSRF_MISSING_TOKEN,
        security_invariant=SecurityInvariant.ORIGIN_INTEGRITY,
        entry_point="POST /cmd",
        sensitive_sink="dispatch_command",
        required_capability=AttackerCapability.BROWSER_CROSS_ORIGIN,
    )
    assert identity1.structural_hash != identity_distinct.structural_hash


def test_semantic_finding_identity_from_finding_factory() -> None:
    """from_finding factory correctly infers invariants, root cause families, and sinks."""
    ev = CodeEvidence(
        evidence_id="ev_sink_1",
        file_path="services/dispatch.py",
        start_line=50,
        end_line=55,
        snippet="os.system(cmd)",
        role=CodeEvidenceRole.SINK,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )
    finding = _make_dummy_finding(
        finding_id="find_cmd_1",
        title="Remote Command Execution via /run",
        file_path="services/dispatch.py",
        start_line=50,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        code_evidence=[ev],
        rule_id="SEM-CMD-001",
    )

    identity = SemanticFindingIdentity.from_finding(finding)
    assert identity.root_cause_family == RootCauseFamily.COMMAND_INJECTION_UNESCAPED
    assert identity.security_invariant == SecurityInvariant.INPUT_NEUTRALIZATION
    assert identity.sensitive_sink == "os.system(cmd)"
    assert len(identity.structural_hash) == 16


# =========================================================================
# 2. Evidence-Preserving Deduplication Engine Tests
# =========================================================================

def test_semantic_deduplicator_merges_same_flaw_and_preserves_all_evidence() -> None:
    """Findings sharing the same root cause are merged while retaining all code evidence roles."""
    ev1 = CodeEvidence(
        evidence_id="ev_user_input",
        file_path="routes/api.py",
        start_line=12,
        end_line=14,
        snippet="payload = request.get_json()",
        role=CodeEvidenceRole.USER_INPUT,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )
    ev2 = CodeEvidence(
        evidence_id="ev_propagation",
        file_path="routes/api.py",
        start_line=18,
        end_line=20,
        snippet="executor.dispatch(payload)",
        role=CodeEvidenceRole.PROPAGATION,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )
    ev3 = CodeEvidence(
        evidence_id="ev_sink",
        file_path="core/engine.py",
        start_line=100,
        end_line=105,
        snippet="subprocess.run(cmd, shell=True)",
        role=CodeEvidenceRole.SINK,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )
    ev4 = CodeEvidence(
        evidence_id="ev_guard",
        file_path="core/guard.py",
        start_line=30,
        end_line=35,
        snippet="if not is_valid(cmd): raise Error()",
        role=CodeEvidenceRole.EXPECTED_CONTROL,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )

    gap1 = ProofGap(
        gap_id="gap_1",
        finding_id="find_a",
        target_symbol="is_valid",
        description="Need verification of bypass in is_valid regex",
        status=ProofGapStatus.OPEN,
    )
    gap2 = ProofGap(
        gap_id="gap_2",
        finding_id="find_b",
        target_symbol="executor.dispatch",
        description="Verify thread-safety of dispatch queue",
        status=ProofGapStatus.OPEN,
    )

    finding_a = _make_dummy_finding(
        finding_id="find_a",
        title="Unauthenticated Command Execution in Dispatch Engine",
        file_path="routes/api.py",
        start_line=12,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        code_evidence=[ev1, ev2],
        proof_gaps=[gap1],
        contributing_worker="worker_alpha",
    )
    finding_b = _make_dummy_finding(
        finding_id="find_b",
        title="Shell Injection in core engine subprocess call",
        file_path="core/engine.py",
        start_line=100,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        code_evidence=[ev3, ev4],
        proof_gaps=[gap2],
        contributing_worker="worker_beta",
    )

    # Attach equivalent semantic identities
    shared_identity = SemanticFindingIdentity(
        root_cause_family=RootCauseFamily.COMMAND_INJECTION_UNESCAPED,
        security_invariant=SecurityInvariant.INPUT_NEUTRALIZATION,
        entry_point="POST /api/run",
        sensitive_sink="subprocess.run",
        required_capability=AttackerCapability.NETWORK_UNAUTHENTICATED,
    )
    finding_a.metadata["semantic_identity"] = shared_identity.model_dump()
    finding_b.metadata["semantic_identity"] = shared_identity.model_dump()

    deduplicator = SemanticDeduplicator()
    result = deduplicator.deduplicate([finding_a, finding_b])

    assert len(result.consolidated_findings) == 1
    assert len(result.merge_records) == 1

    merged = result.consolidated_findings[0]
    audit = result.merge_records[0]

    assert audit.decision_outcome == EquivalenceOutcome.SAME
    assert audit.equivalence_confidence >= 0.90
    assert "worker_alpha" in audit.contributing_workers
    assert "worker_beta" in audit.contributing_workers

    # Check evidence preservation: all 4 evidence records with their respective roles are present
    merged_roles = {e.role for e in merged.code_evidence}
    assert CodeEvidenceRole.USER_INPUT in merged_roles
    assert CodeEvidenceRole.PROPAGATION in merged_roles
    assert CodeEvidenceRole.SINK in merged_roles
    assert CodeEvidenceRole.EXPECTED_CONTROL in merged_roles
    assert len(merged.code_evidence) == 4

    # Check proof gaps merged without duplication
    assert len(merged.proof_gaps) == 2
    assert {g.target_symbol for g in merged.proof_gaps} == {"is_valid", "executor.dispatch"}

    # Check metadata reflects contributing workers and duplicate finding IDs
    merged_workers = merged.metadata.get("contributing_workers", [])
    assert "worker_alpha" in merged_workers
    assert "worker_beta" in merged_workers
    assert "find_b" in merged.metadata.get("duplicate_finding_ids", [])


def test_semantic_deduplicator_keeps_distinct_findings_separate() -> None:
    """Findings with distinct invariants or root causes are kept distinct."""
    finding_csrf = _make_dummy_finding(
        finding_id="find_csrf",
        title="Missing CSRF Token on Command Dispatch",
        file_path="routes/cmd.py",
        start_line=45,
        category=VulnerabilityCategory.GENERIC,
    )
    identity_csrf = SemanticFindingIdentity(
        root_cause_family=RootCauseFamily.CSRF_MISSING_TOKEN,
        security_invariant=SecurityInvariant.ORIGIN_INTEGRITY,
        entry_point="POST /cmd",
        sensitive_sink="routes/cmd.py:45",
        required_capability=AttackerCapability.BROWSER_CROSS_ORIGIN,
    )
    finding_csrf.metadata["semantic_identity"] = identity_csrf.model_dump()

    finding_auth = _make_dummy_finding(
        finding_id="find_auth",
        title="Missing Authorization Check on Command Dispatch",
        file_path="routes/cmd.py",
        start_line=45,
        category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
    )
    identity_auth = SemanticFindingIdentity(
        root_cause_family=RootCauseFamily.MISSING_AUTHORIZATION,
        security_invariant=SecurityInvariant.AUTHORIZATION_CHECK,
        entry_point="POST /cmd",
        sensitive_sink="routes/cmd.py:45",
        required_capability=AttackerCapability.NETWORK_UNAUTHENTICATED,
    )
    finding_auth.metadata["semantic_identity"] = identity_auth.model_dump()

    deduplicator = SemanticDeduplicator()
    result = deduplicator.deduplicate([finding_csrf, finding_auth])

    assert len(result.consolidated_findings) == 2
    assert result.merged_count == 0


# =========================================================================
# 3. Path-Specific Adversarial Verification Tests
# =========================================================================

def test_path_adversarial_verification_effective_guard_rejects_finding(tmp_path: Path) -> None:
    """An effective, unbypassed containment guard mandatory on the causal execution path rejects the finding."""
    # Create target file with safe relative path verification
    src_file = tmp_path / "server.py"
    src_file.write_text(
        (
            "def handle_load(name):\n"
            "    target = (safe_root / name).resolve()\n"
            "    if not target.is_relative_to(safe_root):\n"
            "        raise ValueError('Path traversal attempt')\n"
            "    return target.read_text()\n"
        ),
        encoding="utf-8",
    )

    ev_guard = CodeEvidence(
        evidence_id="ev_guard",
        file_path="server.py",
        start_line=3,
        end_line=4,
        snippet="if not target.is_relative_to(safe_root): raise ValueError('Path traversal attempt')",
        role=CodeEvidenceRole.EXPECTED_CONTROL,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )
    ev_sink = CodeEvidence(
        evidence_id="ev_sink",
        file_path="server.py",
        start_line=5,
        end_line=5,
        snippet="return target.read_text()",
        role=CodeEvidenceRole.SINK,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )

    finding = _make_dummy_finding(
        finding_id="find_traversal",
        title="Arbitrary File Read via Path Traversal",
        file_path="server.py",
        start_line=2,
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        code_evidence=[ev_guard, ev_sink],
    )

    verifier = PathAdversarialVerifier(repository_root=tmp_path)
    evaluation = verifier.evaluate_contradiction(finding)

    assert evaluation.contradicts_finding is True
    assert evaluation.reachability == GuardReachability.MANDATORY_ON_PATH
    assert evaluation.effectiveness == GuardEffectiveness.EFFECTIVE_NEUTRALIZATION
    assert "is_relative_to" in evaluation.guard_symbol


def test_path_adversarial_verification_bypassable_guard_does_not_reject(tmp_path: Path) -> None:
    """A bypassable guard on the path does not reject finding; bypass conditions are recorded as proof gaps."""
    src_file = tmp_path / "origin_check.py"
    src_file.write_text(
        (
            "def _enforce_same_origin():\n"
            "    source = get_source()\n"
            "    if not source:\n"
            "        return  # allow it for non-browser clients\n"
            "    check_match(source)\n"
        ),
        encoding="utf-8",
    )

    ev_guard = CodeEvidence(
        evidence_id="ev_origin_guard",
        file_path="origin_check.py",
        start_line=3,
        end_line=4,
        snippet="if not source: return",
        role=CodeEvidenceRole.EXPECTED_CONTROL,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )

    finding = _make_dummy_finding(
        finding_id="find_csrf_bypass",
        title="CSRF Guard Bypass via Missing Origin Header",
        file_path="origin_check.py",
        start_line=1,
        category=VulnerabilityCategory.GENERIC,
        code_evidence=[ev_guard],
    )
    finding.sanitizers_considered = ["_enforce_same_origin"]

    verifier = PathAdversarialVerifier(repository_root=tmp_path)
    evaluation = verifier.evaluate_contradiction(finding)

    assert evaluation.contradicts_finding is False
    assert evaluation.reachability == GuardReachability.BYPASSABLE
    assert len(evaluation.bypass_paths) > 0


def test_path_adversarial_verification_unrelated_sanitizer_in_repo_ignored(tmp_path: Path) -> None:
    """Sanitizers located in unrelated files or modules do not contradict findings on vulnerable paths."""
    vuln_file = tmp_path / "vuln_api.py"
    vuln_file.write_text(
        (
            "def vuln_endpoint(raw_sql):\n"
            "    cursor.execute(raw_sql)\n"
        ),
        encoding="utf-8",
    )

    ev_sink = CodeEvidence(
        evidence_id="ev_sql_sink",
        file_path="vuln_api.py",
        start_line=2,
        end_line=2,
        snippet="cursor.execute(raw_sql)",
        role=CodeEvidenceRole.SINK,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )
    finding = _make_dummy_finding(
        finding_id="find_sqli",
        title="SQL Injection in vuln_endpoint",
        file_path="vuln_api.py",
        start_line=1,
        category=VulnerabilityCategory.SQL_INJECTION,
        code_evidence=[ev_sink],
    )
    finding.counterevidence_notes = ["safe check in server.py mitigates traversal"]

    verifier = PathAdversarialVerifier(repository_root=tmp_path)
    evaluation = verifier.evaluate_contradiction(finding)

    assert evaluation.contradicts_finding is False
    assert evaluation.reachability == GuardReachability.UNRELATED_IN_REPO


# =========================================================================
# 4. SQLite Schema V5 Security Workbench Persistence Tests
# =========================================================================

def test_sqlite_schema_v5_migrations_and_workbench_persistence() -> None:
    """SQLiteStorage Schema V5 correctly records versions, transitions, merges, and provider usage."""
    storage = SQLiteStorage(":memory:")

    # Verify schema version = 5
    with storage._connection() as conn:
        cur = conn.execute("SELECT version FROM schema_version;")
        row = cur.fetchone()
        assert row["version"] == 5

    # 1. Test Finding Versions
    finding_id = "SEM-2026-0001"
    # Ensure parent finding exists
    f = _make_dummy_finding(finding_id, "Sample Flaw", "app.py", 10)
    storage.save_finding(f, "scan_workbench_1")

    storage.save_finding_version(
        version_id="ver_001",
        finding_id=finding_id,
        version_number=1,
        lifecycle_state="candidate",
        confidence="medium",
        severity="high",
        semantic_identity={"root_cause_family": "missing_authorization"},
        snapshot={"title": "Candidate flaw"},
    )
    storage.save_finding_version(
        version_id="ver_002",
        finding_id=finding_id,
        version_number=2,
        lifecycle_state="confirmed",
        confidence="high",
        severity="high",
        semantic_identity={"root_cause_family": "missing_authorization"},
        snapshot={"title": "Confirmed flaw after verification"},
    )

    versions = storage.get_finding_versions(finding_id)
    assert len(versions) == 2
    assert versions[0]["version_number"] == 1
    assert versions[0]["lifecycle_state"] == "candidate"
    assert versions[1]["version_number"] == 2
    assert versions[1]["lifecycle_state"] == "confirmed"
    assert versions[1]["semantic_identity"]["root_cause_family"] == "missing_authorization"

    # 2. Test Lifecycle Transitions
    storage.record_lifecycle_transition(
        transition_id="trans_01",
        finding_id=finding_id,
        from_state="candidate",
        to_state="under_investigation",
        trigger_reason="Assigned to perspective worker",
        actor_or_component="InvestigationCoordinator",
    )
    storage.record_lifecycle_transition(
        transition_id="trans_02",
        finding_id=finding_id,
        from_state="under_investigation",
        to_state="confirmed",
        trigger_reason="Multi-perspective agreement with path evidence",
        actor_or_component="FindingAdjudicator",
    )

    transitions = storage.get_lifecycle_transitions(finding_id)
    assert len(transitions) == 2
    assert transitions[0]["from_state"] == "candidate"
    assert transitions[0]["to_state"] == "under_investigation"
    assert transitions[1]["to_state"] == "confirmed"

    # 3. Test Semantic Merge Persistence
    secondary_id = "SEM-2026-0002"
    f2 = _make_dummy_finding(secondary_id, "Duplicate Flaw", "app.py", 50)
    storage.save_finding(f2, "scan_workbench_1")

    storage.save_semantic_merge(
        merge_id="merge_01",
        primary_finding_id=finding_id,
        secondary_finding_id=secondary_id,
        decision_outcome="same",
        equivalence_confidence=0.95,
        merge_rationale="Identical root cause and shared execution sink",
        evidence_ids_merged=["ev_1", "ev_2"],
        contributing_workers=["worker_1", "worker_2"],
    )

    merges = storage.get_semantic_merges(finding_id)
    assert len(merges) == 1
    assert merges[0]["secondary_finding_id"] == secondary_id
    assert merges[0]["decision_outcome"] == "same"
    assert merges[0]["equivalence_confidence"] == 0.95
    assert "worker_1" in merges[0]["contributing_workers"]

    # 4. Test Provider Usage Persistence
    run_id = "run_perspective_001"
    storage.record_provider_usage(
        usage_id="use_01",
        run_id=run_id,
        worker_id="auth_worker",
        provider_name="nvidia",
        model_name="deepseek-ai/deepseek-r1",
        input_tokens=1500,
        cached_input_tokens=500,
        output_tokens=300,
        total_tokens=1800,
        estimated_cost_usd=0.005,
    )

    usage = storage.get_provider_usage(run_id)
    assert len(usage) == 1
    assert usage[0]["worker_id"] == "auth_worker"
    assert usage[0]["input_tokens"] == 1500
    assert usage[0]["cached_input_tokens"] == 500
    assert usage[0]["output_tokens"] == 300
    assert usage[0]["total_tokens"] == 1800
    assert usage[0]["estimated_cost_usd"] == 0.005


def test_sqlite_v2_to_v5_migration_without_data_loss(tmp_path: Path) -> None:
    """Existing V2 database is upgraded smoothly to V5 without losing legacy scan or finding records."""
    db_file = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db_file))
    conn.executescript(SCHEMA_V2)
    conn.execute(
        """
        INSERT INTO scans (scan_id, target_path, mode, started_at, completed_at, inspection_json, coverage_json)
        VALUES ('legacy_scan', '/repo', 'sequential', '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', '{}', '{}');
        """
    )
    conn.execute(
        """
        INSERT INTO findings (finding_id, scan_id, rule_id, title, category, severity, confidence, file_path, start_line, end_line, fingerprint, validation_status, full_json)
        VALUES ('legacy_find', 'legacy_scan', 'R1', 'Legacy Finding', 'generic', 'high', 'high', 'legacy.py', 1, 10, 'fp1', 'candidate', '{}');
        """
    )
    conn.commit()
    conn.close()

    # Open with SQLiteStorage to trigger auto-migration to V5
    storage = SQLiteStorage(db_file)
    with storage._connection() as c:
        cur = c.execute("SELECT version FROM schema_version;")
        assert cur.fetchone()["version"] == 5

        # Legacy data is intact
        f_cur = c.execute("SELECT finding_id, title, semantic_identity_json FROM findings WHERE finding_id = 'legacy_find';")
        row = f_cur.fetchone()
        assert row["finding_id"] == "legacy_find"
        assert row["title"] == "Legacy Finding"
        assert row["semantic_identity_json"] == "{}"


# =========================================================================
# 5. SARIF 2.1.0 Interoperability Tests
# =========================================================================

def test_sarif_export_and_import_roundtrip() -> None:
    """Exporting findings to SARIF 2.1.0 and importing them back preserves locations, codeFlows, and rule metadata."""
    ev_entry = CodeEvidence(
        evidence_id="ev_e1",
        file_path="src/router.py",
        start_line=15,
        end_line=20,
        snippet="def route_handler(req):",
        role=CodeEvidenceRole.ENTRYPOINT,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )
    ev_sink = CodeEvidence(
        evidence_id="ev_s1",
        file_path="src/backend.py",
        start_line=85,
        end_line=90,
        snippet="os.system(req.cmd)",
        role=CodeEvidenceRole.SINK,
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
        verification_status=EvidenceVerificationStatus.VERIFIED,
    )

    finding = _make_dummy_finding(
        finding_id="SEM-SARIF-001",
        title="Command Injection in router backend dispatch",
        file_path="src/backend.py",
        start_line=85,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        code_evidence=[ev_entry, ev_sink],
    )
    finding.cwe_ids = ["CWE-78"]
    finding.impact = "Arbitrary code execution on host"

    # Export to SARIF
    sarif_str = SARIFExporter.export([finding], tool_name="Semantiq Security", tool_version="0.1.0")
    sarif_dict = json.loads(sarif_str)

    assert sarif_dict["version"] == "2.1.0"
    assert sarif_dict["$schema"] == "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"

    run = sarif_dict["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]

    assert result["ruleId"] == "SEM-AUTH-001"
    assert result["level"] == "error"
    assert "codeFlows" in result
    assert len(result["codeFlows"]) == 1
    thread_flow = result["codeFlows"][0]["threadFlows"][0]
    assert len(thread_flow["locations"]) == 2

    # Import back into Finding candidates
    importer = SARIFImporter()
    imported_findings = importer.import_sarif(sarif_dict)

    assert len(imported_findings) == 1
    imported = imported_findings[0]

    assert imported.rule_id == "SEM-AUTH-001"
    assert imported.severity == SeverityLevel.HIGH
    assert imported.file_path == "src/backend.py"
    assert imported.start_line == 85
    assert len(imported.code_evidence) == 2
    assert imported.lifecycle_state == FindingLifecycleState.CANDIDATE


def test_sarif_importer_defensive_validation() -> None:
    """SARIF importer gracefully handles malformed, partial, or external SARIF without crashing."""
    importer = SARIFImporter()

    # Empty dictionary raises ValueError
    with pytest.raises(ValueError, match="Unsupported SARIF version"):
        importer.import_sarif({})

    # Valid SARIF version but empty runs
    assert importer.import_sarif({"version": "2.1.0", "runs": []}) == []

    # Missing results list returns empty
    assert importer.import_sarif({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test"}}}]}) == []

    # Result with missing locations and unrecognized severity level maps safely
    malformed_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ExternalScanner"}},
                "results": [
                    {
                        "ruleId": "EXT-999",
                        "message": {"text": "A problem occurred"},
                        "level": "non_standard_level",
                    }
                ],
            }
        ],
    }
    imported = importer.import_sarif(malformed_sarif)
    assert len(imported) == 1
    assert imported[0].rule_id == "EXT-999"
    assert imported[0].severity == SeverityLevel.MEDIUM
    assert imported[0].file_path == "unknown"
