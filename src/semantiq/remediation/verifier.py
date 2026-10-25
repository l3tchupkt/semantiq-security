"""Patch verification and regression testing."""

from __future__ import annotations

import ast
from pathlib import Path

from semantiq.analysis.python_ast import analyze_python_source
from semantiq.analysis.regex_patterns import analyze_javascript_source
from semantiq.models import PatchProposal, PatchVerificationResult


def verify_patch(
    repository_root: Path,
    patch: PatchProposal,
) -> PatchVerificationResult:
    """Verify that a proposed patch eliminates the targeted vulnerability without syntax breakage."""
    target_file = repository_root / patch.file_path
    if not target_file.exists():
        return PatchVerificationResult(
            finding_id=patch.finding_id,
            status="inconclusive",
            summary=f"File {patch.file_path} not found.",
        )

    if not patch.unified_diff:
        return PatchVerificationResult(
            finding_id=patch.finding_id,
            status="inconclusive",
            summary="Empty patch provided.",
        )

    try:
        original_content = target_file.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return PatchVerificationResult(
            finding_id=patch.finding_id,
            status="inconclusive",
            summary=f"Cannot read file: {error}",
        )

    # Apply diff to content in a temporary scratchbed
    # We parse the diff additions/removals
    lines = original_content.splitlines(keepends=True)
    patched_lines = list(lines)

    # Simplified patch apply for single-hunk diffs
    diff_lines = patch.unified_diff.splitlines()
    for d_line in diff_lines:
        if d_line.startswith("-") and not d_line.startswith("---"):
            old_str = d_line[1:].strip()
            for idx, pl in enumerate(patched_lines):
                if pl.strip() == old_str:
                    patched_lines[idx] = ""  # remove
                    break
        elif d_line.startswith("+") and not d_line.startswith("+++"):
            new_str = d_line[1:] + "\n"
            # insert at first empty slot or append
            for idx, pl in enumerate(patched_lines):
                if pl == "":
                    patched_lines[idx] = new_str
                    break

    patched_content = "".join(patched_lines)

    # 1. Syntax check for Python
    if patch.file_path.endswith(".py"):
        try:
            ast.parse(patched_content, filename=patch.file_path)
        except SyntaxError as syn_err:
            return PatchVerificationResult(
                finding_id=patch.finding_id,
                status="regression_detected",
                summary=f"Patch introduced Python syntax error: {syn_err}",
                re_scan_finding_count=1,
            )

        # 2. Re-scan patched content
        findings = analyze_python_source(patch.file_path, patched_content)
        matching = [f for f in findings if f.finding_id == patch.finding_id]
        if not matching:
            return PatchVerificationResult(
                finding_id=patch.finding_id,
                status="fixed",
                summary="Vulnerability verified FIXED: finding no longer detected in patched AST.",
                re_scan_finding_count=len(findings),
            )
        else:
            return PatchVerificationResult(
                finding_id=patch.finding_id,
                status="still_vulnerable",
                summary="Vulnerability PERSISTS: finding still detected after patch application.",
                re_scan_finding_count=len(matching),
            )

    elif patch.file_path.endswith((".js", ".ts")):
        findings = analyze_javascript_source(patch.file_path, patched_content)
        matching = [f for f in findings if f.finding_id == patch.finding_id]
        if not matching:
            return PatchVerificationResult(
                finding_id=patch.finding_id,
                status="fixed",
                summary="Vulnerability verified FIXED in JavaScript/TypeScript source.",
                re_scan_finding_count=len(findings),
            )
        else:
            return PatchVerificationResult(
                finding_id=patch.finding_id,
                status="still_vulnerable",
                summary="Vulnerability PERSISTS after patch application.",
                re_scan_finding_count=len(matching),
            )

    return PatchVerificationResult(
        finding_id=patch.finding_id,
        status="inconclusive",
        summary="Unsupported language for automated AST patch verification.",
    )
