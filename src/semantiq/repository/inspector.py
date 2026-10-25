"""Deterministic repository inspection and inventory enumeration."""

from __future__ import annotations

import os
from pathlib import Path

import pathspec

from semantiq.config import ScanConfig
from semantiq.exceptions import TargetNotFoundError
from semantiq.models import RepositoryInspection
from semantiq.repository.git import inspect_git
from semantiq.repository.safepath import resolve_safe_path

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".pyi": "python",
    ".pyx": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "typescript",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".ini": "ini",
    ".env": "env",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c_header",
    ".hpp": "cpp_header",
    ".rb": "ruby",
    ".php": "php",
    ".html": "html",
    ".sql": "sql",
}

KNOWN_CONFIG_FILENAMES = {
    "security.md",
    "pyproject.toml",
    "requirements.txt",
    "pipfile",
    "setup.py",
    "setup.cfg",
    "package.json",
    "pnpm-lock.yaml",
    "package-lock.json",
    "cargo.toml",
    "go.mod",
    "dockerfile",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
    ".semantiq.toml",
}


def is_binary_file(file_path: Path) -> bool:
    """Check if file is binary by looking for null bytes in initial 8KB."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except OSError:
        return True


class RepositoryInspector:
    """Inspects repositories, detects languages, and produces filtered inventories."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    def inspect(self, target_path: str | Path) -> RepositoryInspection:
        """Execute full repository inspection and file enumeration."""
        target = Path(target_path).expanduser().resolve()
        if not target.exists() or not target.is_dir():
            raise TargetNotFoundError(f"Repository target not found: {target_path}")

        root_path = target
        git_meta = inspect_git(root_path)

        # Build pathspec matcher
        exclude_spec = pathspec.PathSpec.from_lines(
            "gitignore", self.config.exclude_patterns
        )
        include_spec = (
            pathspec.PathSpec.from_lines("gitignore", self.config.include_patterns)
            if self.config.include_patterns
            else None
        )

        in_scope_files: list[str] = []
        excluded_files: list[str] = []
        config_files: list[str] = []
        languages: dict[str, int] = {}
        total_files = 0
        security_policy_path: str | None = None

        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
            # Prune excluded directories early to save I/O
            rel_dir = os.path.relpath(dirpath, root_path).replace("\\", "/")
            if rel_dir != "." and exclude_spec.match_file(f"{rel_dir}/"):
                dirnames.clear()
                continue

            for fname in filenames:
                total_files += 1
                rel_file = os.path.normpath(
                    os.path.join(rel_dir, fname) if rel_dir != "." else fname
                ).replace("\\", "/")

                full_path = root_path / rel_file

                # Validate path safety
                try:
                    resolve_safe_path(root_path, full_path)
                except Exception:
                    excluded_files.append(rel_file)
                    continue

                # Check if excluded
                if exclude_spec.match_file(rel_file):
                    excluded_files.append(rel_file)
                    continue

                # Check include patterns if configured
                if include_spec and not include_spec.match_file(rel_file):
                    excluded_files.append(rel_file)
                    continue

                # Check file size limit
                try:
                    stat_info = full_path.stat()
                    if stat_info.st_size > self.config.max_file_size_bytes:
                        excluded_files.append(rel_file)
                        continue
                except OSError:
                    excluded_files.append(rel_file)
                    continue

                # Check binary file
                if is_binary_file(full_path):
                    excluded_files.append(rel_file)
                    continue

                # Identify config files
                fname_lower = fname.lower()
                if fname_lower in KNOWN_CONFIG_FILENAMES or rel_file.lower().endswith(".github/security.md"):
                    config_files.append(rel_file)
                    if fname_lower == "security.md" and security_policy_path is None:
                        security_policy_path = rel_file

                # Identify language
                ext = full_path.suffix.lower()
                lang = LANGUAGE_EXTENSIONS.get(ext)
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1

                in_scope_files.append(rel_file)

                # Stop if max files threshold reached
                if len(in_scope_files) >= self.config.max_files:
                    break

            if len(in_scope_files) >= self.config.max_files:
                break

        in_scope_files.sort()
        excluded_files.sort()
        config_files.sort()

        return RepositoryInspection(
            root_path=str(root_path),
            is_git=git_meta.is_git,
            git_revision=git_meta.revision,
            git_branch=git_meta.branch,
            is_dirty=git_meta.is_dirty,
            languages=languages,
            total_files=total_files,
            in_scope_files=in_scope_files,
            excluded_files=excluded_files,
            config_files=config_files,
            security_policy_path=security_policy_path,
        )
