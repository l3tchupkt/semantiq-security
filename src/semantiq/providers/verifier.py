"""Source reference and citation verification for AI-generated findings."""

from __future__ import annotations

from pathlib import Path

from semantiq.models import Finding


def verify_finding_citations(repository_root: Path, finding: Finding) -> tuple[bool, str]:
    """Verify that file paths, line ranges, and code excerpts cited by AI exist on disk.

    Returns:
        (is_valid, reason): True if verified against real repository files, False otherwise.
    """
    file_path = repository_root / finding.file_path
    if not file_path.exists() or not file_path.is_file():
        return False, f"Cited file does not exist in repository: {finding.file_path}"

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
    except OSError as error:
        return False, f"Could not read cited file: {error}"

    total_lines = len(lines)
    if finding.start_line < 1 or finding.start_line > total_lines:
        return False, f"Cited start line {finding.start_line} exceeds file length ({total_lines} lines)"

    if finding.end_line < finding.start_line or finding.end_line > total_lines:
        return False, f"Cited end line {finding.end_line} invalid for file length ({total_lines} lines)"

    # Check evidence snippet overlap if present
    if finding.code_evidence:
        cited_snippet = finding.code_evidence[0].snippet.strip()
        actual_lines = lines[finding.start_line - 1 : finding.end_line]
        actual_block = "\n".join(actual_lines).strip()

        # Clean formatting prefixes like ' > 12 | ' if present
        cleaned_cited = "\n".join(
            line.split("|", 1)[1].strip() if "|" in line else line.strip()
            for line in cited_snippet.splitlines()
        ).strip()

        if cleaned_cited and cleaned_cited not in content and actual_block not in cited_snippet:
            # Tolerant partial check
            first_cited_line = cleaned_cited.splitlines()[0].strip()
            if first_cited_line and first_cited_line not in content:
                return False, "Cited code excerpt does not match source content at cited lines"

    return True, "Citations successfully verified against local repository files."
