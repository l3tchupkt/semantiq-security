"""Unit tests for patch proposal generation and patch verification."""

from pathlib import Path

from semantiq.models import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    VulnerabilityCategory,
)
from semantiq.remediation.generator import propose_patch
from semantiq.remediation.verifier import verify_patch


def test_propose_and_verify_patch(tmp_path: Path) -> None:
    # Create vulnerable sample file
    vuln_file = tmp_path / "service.py"
    vuln_file.write_text(
        """import subprocess

def run_task(cmd):
    subprocess.run(cmd, shell=True)
""",
        encoding="utf-8",
    )

    finding = Finding(
        finding_id="sqf_rem_001",
        occurrence_id="occ_rem_001",
        rule_id="SQ-PY-001",
        title="Command Injection via shell=True",
        summary="shell=True used with dynamic argument",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="service.py",
        start_line=4,
        end_line=4,
        fingerprint="semantiq/v1:sha256:testrem",
        discovery_backend="python_ast",
    )

    # 1. Propose patch
    patch = propose_patch(finding, tmp_path)
    assert patch.unified_diff != ""
    assert "-    subprocess.run(cmd, shell=True)" in patch.unified_diff
    assert "+    subprocess.run(cmd, shell=False)" in patch.unified_diff

    # 2. Verify patch
    ver_result = verify_patch(tmp_path, patch)
    assert ver_result.status == "fixed"
    assert "FIXED" in ver_result.summary
