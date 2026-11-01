"""Comprehensive validation and negative tests for evidence contract, proof gaps, and finalizer."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

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
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.storage.sqlite import SCHEMA_V2, SQLiteStorage
from semantiq.validation.contract_finalizer import (
    ScanContractFinalizer,
    ViolationCode,
)


@pytest.fixture
def target_repo(tmp_path: Path) -> Path:
    """Create a mock repository with multi-file codebases for evidence testing."""
    api_dir = tmp_path / "api"
    api_dir.mkdir(parents=True)
    services_dir = tmp_path / "services"
    services_dir.mkdir(parents=True)

    # api/routes.py
    routes_py = api_dir / "routes.py"
    routes_py.write_text(
        (
            "# Route Handler\n"
            "from flask import request\n"
            "from services.executor import run_query\n\n"
            "@app.route('/query')\n"
            "def query_endpoint():\n"
            "    user_param = request.args.get('input')\n"
            "    result = run_query(user_param)\n"
            "    return result\n"
        ),
        encoding="utf-8",
    )

    # services/executor.py
    executor_py = services_dir / "executor.py"
    executor_py.write_text(
        (
            "# Executor Service\n"
            "import os\n"
            "import sqlite3\n\n"
            "def run_query(raw_input):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    # Missing parameterized query\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM users WHERE name = '{raw_input}'\"\n"
            "    return cursor.execute(query).fetchall()\n"
        ),
        encoding="utf-8",
    )

    return tmp_path


def test_evidence_roles_and_multi_file_causal_path(target_repo: Path) -> None:
    """Verify evidence pieces spanning all 7 semantic roles across multi-file paths are verified."""
    ev_user_input = CodeEvidence(
        evidence_id="ev_input",
        file_path="api/routes.py",
        start_line=7,
        end_line=7,
        snippet="user_param = request.args.get('input')",
        role=CodeEvidenceRole.USER_INPUT,
        explanation="Attacker-controllable input supplied via HTTP query parameter",
        provenance=EvidenceProvenance.LOCAL_REPOSITORY,
    )
    ev_entrypoint = CodeEvidence(
        evidence_id="ev_entry",
        file_path="api/routes.py",
        start_line=5,
        end_line=6,
        snippet="@app.route('/query')\ndef query_endpoint():",
        role=CodeEvidenceRole.ENTRYPOINT,
        explanation="Public HTTP entrypoint",
    )
    ev_propagation = CodeEvidence(
        evidence_id="ev_prop",
        file_path="api/routes.py",
        start_line=8,
        end_line=8,
        snippet="result = run_query(user_param)",
        role=CodeEvidenceRole.PROPAGATION,
        explanation="Untrusted argument propagated into service layer function",
    )
    ev_root_control = CodeEvidence(
        evidence_id="ev_root_ctrl",
        file_path="api/routes.py",
        start_line=6,
        end_line=6,
        snippet="def query_endpoint():",
        role=CodeEvidenceRole.ROOT_CONTROL,
        explanation="No authentication or authorization guard present on handler",
    )
    ev_sink = CodeEvidence(
        evidence_id="ev_sink",
        file_path="services/executor.py",
        start_line=10,
        end_line=10,
        snippet="return cursor.execute(query).fetchall()",
        role=CodeEvidenceRole.SINK,
        explanation="Dangerous SQL query execution sink",
    )
    ev_outcome = CodeEvidence(
        evidence_id="ev_outcome",
        file_path="services/executor.py",
        start_line=9,
        end_line=10,
        snippet="query = f\"SELECT * FROM users WHERE name = '{raw_input}'\"\n    return cursor.execute(query).fetchall()",
        role=CodeEvidenceRole.OUTCOME,
        explanation="Arbitrary SQL injection allowing unauthenticated data exfiltration",
    )
    ev_expected_control = CodeEvidence(
        evidence_id="ev_exp_ctrl",
        file_path="services/executor.py",
        start_line=7,
        end_line=7,
        snippet="# Missing parameterized query",
        role=CodeEvidenceRole.EXPECTED_CONTROL,
        explanation="Parameterized query placeholder required to enforce safety invariant",
    )

    finding = Finding(
        finding_id="sqf_sqli_001",
        occurrence_id="occ_001",
        rule_id="SQ-SQLI-001",
        title="SQL Injection via Unsanitized Input",
        summary="Attacker controls SQL query structure leading to full database compromise.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="services/executor.py",
        start_line=10,
        end_line=10,
        locations=[SourceLocation(file_path="services/executor.py", start_line=10, end_line=10, role="sink")],
        code_evidence=[
            ev_user_input,
            ev_entrypoint,
            ev_propagation,
            ev_root_control,
            ev_sink,
            ev_outcome,
            ev_expected_control,
        ],
        root_cause_evidence_refs=[
            "ev_input",
            "ev_entry",
            "ev_prop",
            "ev_root_ctrl",
            "ev_sink",
            "ev_outcome",
            "ev_exp_ctrl",
        ],
        lifecycle_state=FindingLifecycleState.CONFIRMED,
    )

    finalizer = ScanContractFinalizer(target_repo)
    report = finalizer.finalize([finding], scan_id="scan_roles_test")

    assert report.is_sealed is True
    assert report.valid_findings_count == 1
    assert report.rejected_findings_count == 0
    assert report.error_count == 0
    assert report.overall_security_score == 9.5  # Critical + High confidence

    # Check evidence verification statuses
    finalized_f = report.finalized_findings[0]
    for ev in finalized_f.code_evidence:
        assert ev.verification_status == EvidenceVerificationStatus.VERIFIED


def test_detection_of_invalid_citations(target_repo: Path) -> None:
    """Ensure invalid citations (non-existent file, out-of-bounds line, hallucinated snippet) are rejected."""
    finalizer = ScanContractFinalizer(target_repo)

    # 1. Nonexistent file
    f_fnf = Finding(
        finding_id="sqf_fnf",
        occurrence_id="occ_fnf",
        rule_id="SQ-TEST-001",
        title="Finding in Phantom File",
        summary="Refers to an imaginary module.",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="api/imaginary.py",
        start_line=1,
        end_line=5,
    )

    report_fnf = finalizer.finalize([f_fnf])
    assert report_fnf.is_sealed is False
    assert report_fnf.rejected_findings_count == 1
    assert any(v.code == ViolationCode.FILE_NOT_FOUND for v in report_fnf.violations)
    assert f_fnf.lifecycle_state == FindingLifecycleState.REJECTED

    # 2. Out-of-bounds line
    f_oob = Finding(
        finding_id="sqf_oob",
        occurrence_id="occ_oob",
        rule_id="SQ-TEST-002",
        title="Finding with Line Beyond EOF",
        summary="Start line exceeds total line count.",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="api/routes.py",
        start_line=500,
        end_line=510,
    )

    report_oob = finalizer.finalize([f_oob])
    assert report_oob.is_sealed is False
    assert any(v.code == ViolationCode.OUT_OF_BOUNDS_LINE for v in report_oob.violations)

    # 3. Hallucinated snippet that does not match disk
    f_hallu = Finding(
        finding_id="sqf_hallu",
        occurrence_id="occ_hallu",
        rule_id="SQ-TEST-003",
        title="Hallucinated Code Excerpt",
        summary="Cites code that never existed in the target file.",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="api/routes.py",
        start_line=1,
        end_line=3,
        code_evidence=[
            CodeEvidence(
                evidence_id="ev_hallu",
                file_path="api/routes.py",
                start_line=1,
                end_line=3,
                snippet="eval(untrusted_system_call_param)",
                explanation="Nonexistent snippet",
            )
        ],
    )

    report_hallu = finalizer.finalize([f_hallu])
    assert report_hallu.is_sealed is False
    assert any(v.code == ViolationCode.INVALID_CITATION for v in report_hallu.violations)


def test_detection_of_stale_citations(target_repo: Path) -> None:
    """Ensure stale citations where snippet exists but line numbers shifted produce STALE_CITATION warning."""
    finalizer = ScanContractFinalizer(target_repo)

    # 'from flask import request' is at line 2 in api/routes.py, but cited at lines 8-9
    f_stale = Finding(
        finding_id="sqf_stale",
        occurrence_id="occ_stale",
        rule_id="SQ-TEST-004",
        title="Shifted Code Finding",
        summary="Valid snippet that moved to different lines after refactoring.",
        category=VulnerabilityCategory.GENERIC,
        severity=SeverityLevel.LOW,
        confidence=ConfidenceLevel.MEDIUM,
        file_path="api/routes.py",
        start_line=8,
        end_line=9,
        code_evidence=[
            CodeEvidence(
                evidence_id="ev_stale",
                file_path="api/routes.py",
                start_line=8,
                end_line=9,
                snippet="from flask import request",
                explanation="Import shifted",
            )
        ],
    )

    report_stale = finalizer.finalize([f_stale])
    assert any(v.code == ViolationCode.STALE_CITATION for v in report_stale.violations)
    assert f_stale.code_evidence[0].verification_status == EvidenceVerificationStatus.STALE


def test_open_proof_gaps_demote_confirmed_state(target_repo: Path) -> None:
    """Ensure unproven runtime assumptions prevent findings from silently becoming CONFIRMED."""
    finding = Finding(
        finding_id="sqf_gap_test",
        occurrence_id="occ_gap_test",
        rule_id="SQ-AUTH-001",
        title="Unverified Queue Consumer Bypass",
        summary="Worker assumes messages are pre-authorized without local signature validation.",
        category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="api/routes.py",
        start_line=5,
        end_line=9,
        lifecycle_state=FindingLifecycleState.CONFIRMED,
        validation_status=ValidationStatus.VALIDATED,
        proof_gaps=[
            ProofGap(
                gap_id="gap_01",
                description="Whether reverse proxy verifies JWT before forwarding to route handler",
                rationale="If proxy enforces JWT, route is unreachable unauthenticated",
                target_symbol="query_endpoint",
                resolution_criteria="Inspect proxy configuration or deployment boundary",
                status=ProofGapStatus.OPEN,
            )
        ],
    )

    finalizer = ScanContractFinalizer(target_repo)
    report = finalizer.finalize([finding])

    finalized_f = report.finalized_findings[0]
    # Finding must be demoted from CONFIRMED to PARTIALLY_CONFIRMED
    assert finalized_f.lifecycle_state == FindingLifecycleState.PARTIALLY_CONFIRMED
    assert finalized_f.validation_status == ValidationStatus.EVIDENCE_SUPPORTED
    assert any(v.code == ViolationCode.UNRESOLVED_PROOF_GAP for v in report.violations)


def test_detection_of_contradictory_findings(target_repo: Path) -> None:
    """Ensure findings claiming vulnerability when counterevidence proves mitigation are rejected."""
    finding = Finding(
        finding_id="sqf_contra",
        occurrence_id="occ_contra",
        rule_id="SQ-XSS-001",
        title="Claimed Reflected XSS",
        summary="Attacker can reflect script tags into output response.",
        category=VulnerabilityCategory.CROSS_SITE_SCRIPTING,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="api/routes.py",
        start_line=5,
        end_line=9,
        counterevidence=["Sanitizer applied: output is passed through html.escape before return"],
        lifecycle_state=FindingLifecycleState.CONFIRMED,
    )

    finalizer = ScanContractFinalizer(target_repo)
    report = finalizer.finalize([finding])

    assert report.is_sealed is False
    assert report.rejected_findings_count == 1
    assert any(v.code == ViolationCode.CONTRADICTORY_FINDING for v in report.violations)
    assert finding.lifecycle_state == FindingLifecycleState.REJECTED


def test_detection_of_duplicate_findings(target_repo: Path) -> None:
    """Ensure duplicate findings at identical locations are detected and marked DUPLICATE."""
    f1 = Finding(
        finding_id="sqf_dup_1",
        occurrence_id="occ_1",
        rule_id="SQ-SQLI-001",
        title="SQL Injection at Sink",
        summary="First duplicate finding candidate.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="services/executor.py",
        start_line=10,
        end_line=10,
    )
    f2 = Finding(
        finding_id="sqf_dup_2",
        occurrence_id="occ_2",
        rule_id="SQ-SQLI-001",
        title="Identical SQL Injection at Sink",
        summary="Second duplicate finding candidate targeting identical location.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="services/executor.py",
        start_line=10,
        end_line=10,
    )

    finalizer = ScanContractFinalizer(target_repo)
    report = finalizer.finalize([f1, f2])

    assert report.valid_findings_count == 1
    assert report.rejected_findings_count == 1
    assert any(v.code == ViolationCode.DUPLICATE_FINDING for v in report.violations)
    assert f2.lifecycle_state == FindingLifecycleState.DUPLICATE


def test_sqlite_v2_to_v3_migration_preserves_records(tmp_path: Path) -> None:
    """Verify clean SQLite migration from V2 schema to V3 without losing existing scans/findings."""
    db_file = tmp_path / "legacy.db"

    # 1. Initialize legacy V2 database
    with sqlite3.connect(db_file) as conn:
        conn.executescript(SCHEMA_V2)
        conn.execute("INSERT INTO schema_version (version) VALUES (2);")
        conn.execute(
            """
            INSERT INTO scans (scan_id, target_path, git_revision, mode, started_at, completed_at, inspection_json, coverage_json)
            VALUES ('scan_v2_legacy', '/mock/path', 'rev_v2', 'standard', '2026-10-25T10:00:00Z', '2026-10-25T10:01:00Z', '{}', '{}');
            """
        )
        conn.execute(
            """
            INSERT INTO findings (finding_id, scan_id, rule_id, title, category, severity, confidence, file_path, start_line, end_line, fingerprint, validation_status, full_json)
            VALUES ('sqf_v2_001', 'scan_v2_legacy', 'SQ-LEGACY-01', 'Legacy Finding', 'command_injection', 'high', 'high', 'app.py', 10, 15, 'fp_v2', 'validated', '{}');
            """
        )
        conn.commit()

    # 2. Open with upgraded SQLiteStorage
    storage = SQLiteStorage(db_file)

    with storage._connection() as conn:
        cur_v = conn.execute("SELECT version FROM schema_version;")
        assert cur_v.fetchone()["version"] >= 3

        # Check new tables exist
        for tbl in ["evidence_records", "evidence_references", "proof_gaps", "adjudications", "finalization_results"]:
            cur_t = conn.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tbl}';")
            assert cur_t.fetchone() is not None

        # Check legacy scan was preserved
        cur_s = conn.execute("SELECT scan_id FROM scans WHERE scan_id = 'scan_v2_legacy';")
        assert cur_s.fetchone()["scan_id"] == "scan_v2_legacy"

        # Check legacy finding was preserved
        cur_f = conn.execute("SELECT finding_id, lifecycle_state FROM findings WHERE finding_id = 'sqf_v2_001';")
        row = cur_f.fetchone()
        assert row["finding_id"] == "sqf_v2_001"
        assert row["lifecycle_state"] == "candidate"


def test_sarif_210_generation_and_evidence_attachment(target_repo: Path) -> None:
    """Verify SARIF 2.1.0 generation attaches causal codeFlows, relatedLocations, and security scores."""
    finding = Finding(
        finding_id="sqf_sarif_test",
        occurrence_id="occ_sarif",
        rule_id="SQ-CMD-001",
        title="OS Command Injection",
        summary="Command injection vulnerability via unquoted argument.",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="api/routes.py",
        start_line=8,
        end_line=8,
        code_evidence=[
            CodeEvidence(
                evidence_id="ev_s1",
                file_path="api/routes.py",
                start_line=7,
                end_line=7,
                snippet="user_param = request.args.get('input')",
                role=CodeEvidenceRole.USER_INPUT,
                explanation="Input entry",
            ),
            CodeEvidence(
                evidence_id="ev_s2",
                file_path="api/routes.py",
                start_line=8,
                end_line=8,
                snippet="result = run_query(user_param)",
                role=CodeEvidenceRole.SINK,
                explanation="Dispatch to execution sink",
            ),
        ],
        root_cause_evidence_refs=["ev_s1", "ev_s2"],
    )

    finalizer = ScanContractFinalizer(target_repo)
    report = finalizer.finalize([finding], scan_id="scan_sarif_01")

    doc = json.loads(report.sarif_output)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"

    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["properties"]["security-severity"] == "9.5"

    result = run["results"][0]
    assert result["level"] == "error"
    assert len(result["codeFlows"]) == 1
    thread_flow = result["codeFlows"][0]["threadFlows"][0]
    assert len(thread_flow["locations"]) == 2
    assert thread_flow["locations"][0]["step"] == 1
    assert "[USER_INPUT]" in thread_flow["locations"][0]["location"]["message"]["text"]


def test_deterministic_ordering_and_security_score(target_repo: Path) -> None:
    """Ensure finalizer orders findings deterministically by severity ranking and computes exact scores."""
    f_low = Finding(
        finding_id="sqf_low",
        occurrence_id="occ_low",
        rule_id="SQ-LOW-01",
        title="Low Severity Info",
        summary="Informational configuration finding.",
        category=VulnerabilityCategory.GENERIC,
        severity=SeverityLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        file_path="api/routes.py",
        start_line=1,
        end_line=2,
    )
    f_crit = Finding(
        finding_id="sqf_crit",
        occurrence_id="occ_crit",
        rule_id="SQ-CRIT-01",
        title="Critical RCE",
        summary="Remote command execution via unsafe deserialization.",
        category=VulnerabilityCategory.UNSAFE_DESERIALIZATION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="services/executor.py",
        start_line=5,
        end_line=7,
    )
    f_high = Finding(
        finding_id="sqf_high",
        occurrence_id="occ_high",
        rule_id="SQ-HIGH-01",
        title="High Severity Bypass",
        summary="Authentication bypass via token confusion.",
        category=VulnerabilityCategory.AUTHENTICATION_BYPASS,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.MEDIUM,
        file_path="api/routes.py",
        start_line=5,
        end_line=6,
    )

    finalizer = ScanContractFinalizer(target_repo)
    report1 = finalizer.finalize([f_low, f_crit, f_high], scan_id="det_scan_01")
    report2 = finalizer.finalize([f_high, f_low, f_crit], scan_id="det_scan_02")

    # Order must be strictly Critical -> High -> Low
    assert [f.finding_id for f in report1.finalized_findings] == ["sqf_crit", "sqf_high", "sqf_low"]
    assert [f.finding_id for f in report2.finalized_findings] == ["sqf_crit", "sqf_high", "sqf_low"]

    # Security score computation
    assert finalizer.calculate_finding_score(f_crit) == 9.5
    assert finalizer.calculate_finding_score(f_high) == 6.4  # 8.0 * 0.8
    assert finalizer.calculate_finding_score(f_low) == 2.0  # 2.0 * 1.0


def test_full_pipeline_persistence_and_adjudication_audit(target_repo: Path, tmp_path: Path) -> None:
    """Verify end-to-end relational persistence of findings, evidence records, references, and proof gaps."""
    db_path = tmp_path / "relational_audit.db"
    storage = SQLiteStorage(db_path)

    finding = Finding(
        finding_id="sqf_audit_001",
        occurrence_id="occ_audit_001",
        rule_id="SQ-AUDIT-001",
        title="Tenant Isolation Breach",
        summary="Tenant ID not scoped in repository access query.",
        category=VulnerabilityCategory.CROSS_TENANT_LEAKAGE,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="services/executor.py",
        start_line=8,
        end_line=10,
        code_evidence=[
            CodeEvidence(
                evidence_id="ev_t1",
                file_path="services/executor.py",
                start_line=8,
                end_line=8,
                snippet="cursor = conn.cursor()",
                role=CodeEvidenceRole.ROOT_CONTROL,
                explanation="Missing tenant WHERE clause",
            )
        ],
        root_cause_evidence_refs=["ev_t1"],
        proof_gaps=[
            ProofGap(
                gap_id="gap_tenant_01",
                description="Verify tenant filter in multi-tenant DB layer",
                rationale="Unscoped tenant exposes all tenants",
                resolution_criteria="Check DB middleware",
                status=ProofGapStatus.OPEN,
            )
        ],
    )

    finalizer = ScanContractFinalizer(target_repo)
    report = finalizer.finalize([finding], scan_id="audit_scan_100")

    storage.save_finalization_report(report, scan_id="audit_scan_100")

    # Verify query interfaces
    persisted_report = storage.get_finalization_report("audit_scan_100")
    assert persisted_report is not None
    assert persisted_report["scan_id"] == "audit_scan_100"

    ev_records = storage.get_evidence_records("sqf_audit_001")
    assert len(ev_records) == 1
    assert ev_records[0].role == CodeEvidenceRole.ROOT_CONTROL

    gaps = storage.get_proof_gaps("sqf_audit_001")
    assert len(gaps) == 1
    assert gaps[0].status == ProofGapStatus.OPEN

    # Update proof gap status
    assert storage.update_proof_gap_status("gap_tenant_01", ProofGapStatus.RESOLVED) is True
    updated_gaps = storage.get_proof_gaps("sqf_audit_001")
    assert updated_gaps[0].status == ProofGapStatus.RESOLVED

    # Verify adjudication history
    adjudications = storage.get_adjudications("sqf_audit_001")
    assert len(adjudications) >= 1
    assert adjudications[0]["lifecycle_state"] in ("partially_confirmed", "candidate")
