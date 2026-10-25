"""Git repository introspection and diff extraction."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import NamedTuple


class GitMetadata(NamedTuple):
    """Extracted Git repository metadata."""
    is_git: bool
    revision: str | None
    branch: str | None
    is_dirty: bool


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Execute git with strict argument arrays and safe execution limits."""
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def inspect_git(repository_path: Path) -> GitMetadata:
    """Detect whether path is a Git repository and extract revision and status."""
    try:
        check = _run_git(["rev-parse", "--is-inside-work-tree"], cwd=repository_path)
        if check.returncode != 0 or check.stdout.strip() != "true":
            return GitMetadata(is_git=False, revision=None, branch=None, is_dirty=False)

        rev_proc = _run_git(["rev-parse", "HEAD"], cwd=repository_path)
        revision = rev_proc.stdout.strip() if rev_proc.returncode == 0 else None

        branch_proc = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repository_path)
        branch = branch_proc.stdout.strip() if branch_proc.returncode == 0 else None

        status_proc = _run_git(["status", "--porcelain"], cwd=repository_path)
        is_dirty = bool(status_proc.stdout.strip()) if status_proc.returncode == 0 else False

        return GitMetadata(
            is_git=True,
            revision=revision,
            branch=branch,
            is_dirty=is_dirty,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return GitMetadata(is_git=False, revision=None, branch=None, is_dirty=False)


def get_diff_changed_files(
    repository_path: Path,
    base_revision: str,
    head_revision: str | None = None,
) -> list[str]:
    """Retrieve list of modified files between two Git revisions or working tree."""
    args = ["diff", "--name-only", base_revision]
    if head_revision:
        args.append(head_revision)

    try:
        proc = _run_git(args, cwd=repository_path)
        if proc.returncode != 0:
            return []
        lines = [line.strip().replace("\\", "/") for line in proc.stdout.splitlines() if line.strip()]
        return sorted(set(lines))
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
