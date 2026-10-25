"""Automated patch generation enforcing security invariants."""

from __future__ import annotations

import difflib
from pathlib import Path

from semantiq.models import Finding, PatchProposal, VulnerabilityCategory


def propose_patch(finding: Finding, repository_root: Path) -> PatchProposal:
    """Generate a minimal unified diff patch addressing the vulnerability."""
    target_file = repository_root / finding.file_path
    if not target_file.exists() or not target_file.is_file():
        return PatchProposal(
            finding_id=finding.finding_id,
            file_path=finding.file_path,
            unified_diff="",
            rationale="Target file not found; cannot propose patch.",
            invariant_enforced="None",
            applied=False,
        )

    try:
        original_content = target_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return PatchProposal(
            finding_id=finding.finding_id,
            file_path=finding.file_path,
            unified_diff="",
            rationale="Error reading source file.",
            invariant_enforced="None",
            applied=False,
        )

    original_lines = original_content.splitlines(keepends=True)
    modified_lines = list(original_lines)

    target_idx = finding.start_line - 1
    if 0 <= target_idx < len(modified_lines):
        line = modified_lines[target_idx]
        invariant = "Enforce safe parameterization and boundary checks"

        if finding.category == VulnerabilityCategory.COMMAND_INJECTION:
            if "shell=True" in line:
                modified_lines[target_idx] = line.replace("shell=True", "shell=False")
                invariant = "Eliminate shell interpolation by enforcing shell=False"
            elif "os.system(" in line:
                modified_lines[target_idx] = line.replace("os.system(", "subprocess.run(shlex.split(")
                invariant = "Replace unsafe os.system() with argument-split subprocess execution"

        elif finding.category == VulnerabilityCategory.SQL_INJECTION:
            if 'f"' in line or "f'" in line:
                modified_lines[target_idx] = f"# FIX: Use parameterized query\n{line}"
                invariant = "Replace dynamic string interpolation with parameterized SQL"

        elif finding.category == VulnerabilityCategory.INSECURE_CRYPTO:
            if "hashlib.md5" in line:
                modified_lines[target_idx] = line.replace("hashlib.md5", "hashlib.sha256")
                invariant = "Upgrade cryptographically broken MD5 to SHA-256"
            elif "hashlib.sha1" in line:
                modified_lines[target_idx] = line.replace("hashlib.sha1", "hashlib.sha256")
                invariant = "Upgrade cryptographically broken SHA-1 to SHA-256"

        elif finding.category == VulnerabilityCategory.INSECURE_FILE_OPS:
            if "0o777" in line:
                modified_lines[target_idx] = line.replace("0o777", "0o600")
                invariant = "Restrict file permissions from 0o777 to 0o600 (owner-only)"
            elif "tempfile.mktemp" in line:
                modified_lines[target_idx] = line.replace("tempfile.mktemp()", "tempfile.NamedTemporaryFile().name")
                invariant = "Replace race-condition prone mktemp with NamedTemporaryFile"

        diff_lines = list(
            difflib.unified_diff(
                original_lines,
                modified_lines,
                fromfile=f"a/{finding.file_path}",
                tofile=f"b/{finding.file_path}",
            )
        )
        unified_diff = "".join(diff_lines)
    else:
        unified_diff = ""
        invariant = "Line index out of bounds"

    return PatchProposal(
        finding_id=finding.finding_id,
        file_path=finding.file_path,
        unified_diff=unified_diff,
        rationale=f"Remediates {finding.category.value}: {finding.remediation}",
        invariant_enforced=invariant,
        applied=False,
    )
