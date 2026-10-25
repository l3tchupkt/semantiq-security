"""Repository inspection, Git metadata, and safe path resolution."""

from semantiq.repository.git import GitMetadata, get_diff_changed_files, inspect_git
from semantiq.repository.inspector import RepositoryInspector
from semantiq.repository.safepath import (
    has_ntfs_alternate_stream,
    is_windows_reserved_name,
    resolve_safe_path,
)

__all__ = [
    "GitMetadata",
    "RepositoryInspector",
    "get_diff_changed_files",
    "has_ntfs_alternate_stream",
    "inspect_git",
    "is_windows_reserved_name",
    "resolve_safe_path",
]
