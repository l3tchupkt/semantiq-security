"""Safe filesystem path resolution and boundary enforcement."""

from __future__ import annotations

import re
from pathlib import Path

from semantiq.exceptions import (
    PathTraversalError,
    SymlinkEscapeError,
    UnsupportedPathError,
)

# Reserved DOS device names on Windows
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

WINDOWS_RESERVED_PATTERN = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$",
    re.IGNORECASE,
)


def has_ntfs_alternate_stream(path: Path | str) -> bool:
    """Check if any path component attempts an NTFS alternate data stream (e.g., file.txt:stream)."""
    p = Path(path) if isinstance(path, str) else path
    parts = p.parts
    # Skip drive anchor (e.g., 'C:\\') on Windows
    for idx, component in enumerate(parts):
        if idx == 0 and len(component) >= 2 and component[1] == ":":
            continue
        if ":" in component:
            return True
    return False


def is_windows_reserved_name(component: str) -> bool:
    """Check if a filename matches Windows reserved device names."""
    base = component.split(".")[0].upper()
    return base in WINDOWS_RESERVED_NAMES or bool(WINDOWS_RESERVED_PATTERN.match(component))


def resolve_safe_path(
    repository_root: Path | str,
    target_path: Path | str,
    allow_missing: bool = False,
) -> Path:
    """Resolve a target path safely, ensuring it remains strictly within the repository root.

    Raises:
        UnsupportedPathError: If null bytes, NTFS streams, or reserved device names are detected.
        PathTraversalError: If path contains explicit directory traversal escaping root.
        SymlinkEscapeError: If resolved symlink points outside the repository.
    """
    repo = Path(repository_root).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        raise PathTraversalError(f"Repository root directory does not exist: {repository_root}")

    path_str = str(target_path)
    if "\0" in path_str:
        raise UnsupportedPathError("Null bytes in filesystem path are prohibited.")

    if has_ntfs_alternate_stream(target_path):
        raise UnsupportedPathError(
            f"NTFS alternate data streams are prohibited: {target_path}"
        )

    p = Path(target_path).expanduser()
    for component in p.parts:
        if is_windows_reserved_name(component):
            raise UnsupportedPathError(
                f"Path contains reserved device name: {component}"
            )

    # Make absolute relative to repository
    absolute = p if p.is_absolute() else (repo / p)

    try:
        resolved = absolute.resolve(strict=not allow_missing)
    except (OSError, ValueError) as error:
        raise PathTraversalError(f"Cannot resolve filesystem path: {target_path}") from error

    # Verify that resolved path is within repo
    try:
        resolved.relative_to(repo)
    except ValueError as error:
        if absolute.is_symlink():
            raise SymlinkEscapeError(
                f"Symbolic link resolves outside repository boundaries: {target_path} -> {resolved}"
            ) from error
        raise PathTraversalError(
            f"Path escapes repository root: {target_path} -> {resolved}"
        ) from error

    return resolved
