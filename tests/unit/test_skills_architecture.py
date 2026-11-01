"""Unit tests for Phase 6 Provider-Agnostic Skill Architecture and Operational Skills."""

from __future__ import annotations

from pathlib import Path

import pytest

from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    SourceLocation,
    VulnerabilityCategory,
)
from semantiq.skills import (
    BaseSecuritySkill,
    SecuritySkillContract,
    SkillBudget,
    SkillCategory,
    SkillInputContext,
    SkillOutput,
    SkillPermission,
    SkillPermissionDeniedError,
    SkillRegistry,
    TelemetryStatus,
    get_default_registry,
)
from semantiq.skills.operational.base import SkillInputValidationError
from semantiq.skills.operational.patch_risk import MergeRecommendation, PatchRiskAssessmentSkill
from semantiq.skills.operational.scanner_ingest import ScannerIngestionSkill
from semantiq.skills.operational.verify_fix import FixVerificationSkill, FixVerificationStatus
from semantiq.skills.registry import SkillDependencyError, SkillRegistrationError
from semantiq.skills.sandbox import SkillSandbox


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Create a minimal safe repository for skill testing."""
    repo = tmp_path / "test_repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(
        "import os\n"
        "from bottle import route, request\n\n"
        "@route('/cmd')\n"
        "def run_cmd():\n"
        "    cmd = request.query.get('c')\n"
        "    os.system(cmd)\n\n"
        "@route('/safe')\n"
        "def safe_route():\n"
        "    return 'OK'\n",
        encoding="utf-8",
    )
    return repo


class DummySkill(BaseSecuritySkill):
    """Simple test skill for contract and sandbox verification."""

    def __init__(
        self, permissions: list[SkillPermission] | None = None, deps: list[str] | None = None
    ) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.dummy_test",
            name="Dummy Test Skill",
            description="Used for unit testing skill contracts and sandbox boundaries.",
            category=SkillCategory.DISCOVERY,
            required_permissions=permissions or [SkillPermission.FILESYSTEM_READ],
            required_inputs=["repository_root"],
            dependencies=deps or [],
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        # Perform read to verify sandbox
        sandbox.resolve_read_path("app.py")
        return SkillOutput(skill_id=self.contract.skill_id, success=True)


# =============================================================================
# 1. Contract & Registration Tests
# =============================================================================


def test_skill_contract_validation() -> None:
    """Verify that malformed skill contracts are rejected by the registry."""
    reg = SkillRegistry()

    # Invalid ID prefix
    with pytest.raises(SkillRegistrationError, match="must begin with 'sq.skill.'"):
        contract = SecuritySkillContract(
            skill_id="invalid.prefix",
            name="Test",
            description="Desc",
            category=SkillCategory.DISCOVERY,
        )
        reg.validate_contract(contract)

    # Empty name
    with pytest.raises(SkillRegistrationError, match="name cannot be empty"):
        contract = SecuritySkillContract(
            skill_id="sq.skill.test",
            name="",
            description="Desc",
            category=SkillCategory.DISCOVERY,
        )
        reg.validate_contract(contract)

    # Invalid budget
    with pytest.raises(SkillRegistrationError, match="timeout must be positive"):
        contract = SecuritySkillContract.model_construct(
            skill_id="sq.skill.test",
            name="Test",
            description="Desc",
            category=SkillCategory.DISCOVERY,
            budget=SkillBudget.model_construct(timeout_seconds=0.0, max_turns=5),
        )
        reg.validate_contract(contract)


def test_skill_registry_catalog_and_lookup() -> None:
    """Verify standard catalog population, registration, and lookup."""
    reg = get_default_registry()
    assert len(reg.list_skills()) >= 7

    # Filter by category
    disc_skills = reg.list_skills(category=SkillCategory.DISCOVERY)
    assert any(s.contract.skill_id == "sq.skill.finding_discovery" for s in disc_skills)

    # Get by ID
    skill = reg.get("sq.skill.threat_modeling")
    assert skill.contract.name == "Threat Modeling & Architecture Mapping"

    # Unknown skill
    with pytest.raises(KeyError, match="not registered"):
        reg.get("sq.skill.non_existent")


# =============================================================================
# 2. Dependency Resolution & Topological Ordering Tests
# =============================================================================


def test_dependency_resolution_ordering() -> None:
    """Verify topological sorting of dependencies."""
    reg = SkillRegistry()

    # Skill A (no deps)
    skill_a = DummySkill(deps=[])
    skill_a.contract.skill_id = "sq.skill.a"

    # Skill B (depends on A)
    skill_b = DummySkill(deps=["sq.skill.a"])
    skill_b.contract.skill_id = "sq.skill.b"

    # Skill C (depends on B)
    skill_c = DummySkill(deps=["sq.skill.b"])
    skill_c.contract.skill_id = "sq.skill.c"

    reg.register(skill_a)
    reg.register(skill_b)
    reg.register(skill_c)

    ordered = reg.resolve_dependencies(["sq.skill.c"])
    assert ordered == ["sq.skill.a", "sq.skill.b", "sq.skill.c"]


def test_dependency_resolution_cycle_detection() -> None:
    """Verify that circular dependencies are detected and raise SkillDependencyError."""
    reg = SkillRegistry()

    skill_x = DummySkill(deps=["sq.skill.y"])
    skill_x.contract.skill_id = "sq.skill.x"

    skill_y = DummySkill(deps=["sq.skill.x"])
    skill_y.contract.skill_id = "sq.skill.y"

    reg.register(skill_x)
    reg.register(skill_y)

    with pytest.raises(SkillDependencyError, match="Circular dependency detected"):
        reg.resolve_dependencies(["sq.skill.x", "sq.skill.y"])


# =============================================================================
# 3. Dynamic Skill Selection Tests
# =============================================================================


def test_dynamic_skill_selection(sample_repo: Path) -> None:
    """Verify that context attributes dynamically select appropriate skills."""
    reg = get_default_registry()

    # Default full scan
    ctx_scan = SkillInputContext(repository_root=sample_repo)
    skills_scan = reg.select_skills_for_context(ctx_scan)
    assert skills_scan == [
        "sq.skill.threat_modeling",
        "sq.skill.finding_discovery",
        "sq.skill.attack_path_analysis",
        "sq.skill.adversarial_validation",
    ]

    # Patch review
    ctx_patch = SkillInputContext(
        repository_root=sample_repo,
        patch_content="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n",
    )
    skills_patch = reg.select_skills_for_context(ctx_patch)
    assert skills_patch == ["sq.skill.patch_risk_assessment"]

    # External scanner alerts
    ctx_alerts = SkillInputContext(
        repository_root=sample_repo,
        external_alerts=[{"path": "app.py", "message": "SQLi"}],
    )
    skills_alerts = reg.select_skills_for_context(ctx_alerts)
    assert "sq.skill.scanner_ingestion" in skills_alerts


# =============================================================================
# 4. Sandbox & Permission Enforcement Tests
# =============================================================================


def test_sandbox_permission_denial(sample_repo: Path) -> None:
    """Verify that undeclared operations are blocked by the sandbox."""
    # Read-only skill attempts write
    sandbox = SkillSandbox(
        skill_id="sq.skill.test_readonly",
        repository_root=sample_repo,
        granted_permissions={SkillPermission.FILESYSTEM_READ},
    )

    # Allowed read
    safe_path = sandbox.resolve_read_path("app.py")
    assert safe_path.exists()

    # Blocked write
    with pytest.raises(SkillPermissionDeniedError, match="filesystem_write"):
        sandbox.resolve_write_path("output.txt")

    # Blocked process execution
    with pytest.raises(SkillPermissionDeniedError, match="process_execution"):
        sandbox.execute_command(["python", "--version"])

    # Blocked graph query
    with pytest.raises(SkillPermissionDeniedError, match="graph_query"):
        sandbox.verify_graph_access()


def test_sandbox_sensitive_path_blocking(sample_repo: Path) -> None:
    """Verify that sandbox blocks access to sensitive files like .env or credentials."""
    env_file = sample_repo / ".env"
    env_file.write_text("SECRET_KEY=12345", encoding="utf-8")

    sandbox = SkillSandbox(
        skill_id="sq.skill.test_leak",
        repository_root=sample_repo,
        granted_permissions={SkillPermission.FILESYSTEM_READ},
    )

    with pytest.raises(SkillPermissionDeniedError, match="sensitive path pattern"):
        sandbox.resolve_read_path(".env")


# =============================================================================
# 5. Input Validation & Telemetry Tests
# =============================================================================


def test_skill_input_validation(sample_repo: Path) -> None:
    """Verify that skills reject contexts missing required inputs."""
    skill = DummySkill()
    skill.contract.required_inputs = ["repository_root", "target_files"]

    # Missing target_files
    ctx = SkillInputContext(repository_root=sample_repo, target_files=[])
    with pytest.raises(SkillInputValidationError, match="target_files"):
        skill.execute(ctx)


def test_telemetry_recording(sample_repo: Path) -> None:
    """Verify that skill execution telemetry accurately measures latency and tool calls."""
    skill = DummySkill()
    ctx = SkillInputContext(repository_root=sample_repo)

    out = skill.execute(ctx)
    assert out.success is True
    assert out.telemetry["status"] == TelemetryStatus.SUCCESS.value
    assert out.telemetry["latency_seconds"] >= 0.0
    assert out.telemetry["provider"] == "deterministic_engine"


# =============================================================================
# 6. Operational Skills Functional Tests
# =============================================================================


def test_patch_risk_assessment_skill(sample_repo: Path) -> None:
    """Verify PatchRiskAssessmentSkill evaluates syntax, blast radius, and auto-merge."""
    skill = PatchRiskAssessmentSkill()

    # Safe patch
    safe_patch = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -6,2 +6,3 @@\n"
        " def run_cmd():\n"
        "+    # Valid comment\n"
        "     cmd = request.query.get('c')\n"
    )
    ctx_safe = SkillInputContext(repository_root=sample_repo, patch_content=safe_patch)
    out_safe = skill.execute(ctx_safe)
    assert out_safe.success is True
    report_safe = out_safe.artifacts["patch_risk_report"]
    assert report_safe["recommendation"] == MergeRecommendation.SAFE_TO_MERGE.value
    assert report_safe["syntax_valid"] is True


def test_scanner_ingestion_skill(sample_repo: Path) -> None:
    """Verify ScannerIngestionSkill normalizes external alerts into Finding contracts."""
    skill = ScannerIngestionSkill()

    ctx = SkillInputContext(
        repository_root=sample_repo,
        external_alerts=[
            {
                "path": "app.py",
                "line": 6,
                "rule_id": "bandit.B605",
                "message": "Starting a process with a shell: Possible injection",
                "severity": "CRITICAL",
            }
        ],
    )
    out = skill.execute(ctx)
    assert out.success is True
    assert len(out.findings) == 1
    f = out.findings[0]
    assert f.rule_id == "bandit.B605"
    assert f.file_path == "app.py"
    assert f.start_line == 6
    assert f.category == VulnerabilityCategory.COMMAND_INJECTION
    assert f.severity == SeverityLevel.CRITICAL


def test_fix_verification_skill(sample_repo: Path) -> None:
    """Verify FixVerificationSkill confirms whether vulnerability remains reachable."""
    skill = FixVerificationSkill()

    finding = Finding(
        finding_id="find_test_cmd",
        occurrence_id="occ_test_cmd",
        rule_id="SQ-PY-001",
        title="OS Command Injection",
        summary="os.system with untrusted input",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="app.py",
        start_line=6,
        end_line=7,
        locations=[SourceLocation(file_path="app.py", start_line=6, end_line=7)],
        code_evidence=[
            CodeEvidence(
                file_path="app.py",
                start_line=6,
                end_line=7,
                role=CodeEvidenceRole.SINK,
                snippet="os.system(cmd)",
            )
        ],
    )

    ctx = SkillInputContext(repository_root=sample_repo, candidate_findings=[finding])
    out = skill.execute(ctx)
    assert out.success is True
    results = out.artifacts["verification_results"]
    assert len(results) == 1
    assert results[0]["status"] == FixVerificationStatus.STILL_VULNERABLE.value


# =============================================================================
# 7. Reducer & Coordinator Integration Tests
# =============================================================================


def test_coordinator_skill_investigation_workflow(sample_repo: Path) -> None:
    """Verify that InvestigationCoordinator runs dynamic skills and reduces findings."""
    from semantiq.discovery.coordinator import InvestigationCoordinator
    from semantiq.storage.sqlite import SQLiteStorage

    storage = SQLiteStorage(":memory:")
    coord = InvestigationCoordinator(sample_repo, storage=storage)

    ctx = SkillInputContext(repository_root=sample_repo, target_files=["app.py"])
    findings, outputs, reducer_res = coord.coordinate_skill_investigation(ctx)

    assert len(outputs) == 4
    skill_names = [o.skill_id for o in outputs]
    assert "sq.skill.threat_modeling" in skill_names
    assert "sq.skill.finding_discovery" in skill_names
    assert "sq.skill.attack_path_analysis" in skill_names
    assert "sq.skill.adversarial_validation" in skill_names

    assert len(findings) >= 1
    # Check that worker_id and skill_id were preserved in metadata
    assert any("skill_id" in f.metadata for f in findings)
    assert reducer_res.total_raw_findings >= 1
