"""Unit tests for safe path resolution and boundary enforcement."""

import os
from pathlib import Path

import pytest

from semantiq.exceptions import (
    PathTraversalError,
    UnsupportedPathError,
)
from semantiq.repository.safepath import (
    has_ntfs_alternate_stream,
    is_windows_reserved_name,
    resolve_safe_path,
)


def test_resolve_safe_path_valid(tmp_path: Path) -> None:
    subfile = tmp_path / "subdir" / "file.py"
    subfile.parent.mkdir(parents=True)
    subfile.write_text("print('hello')", encoding="utf-8")

    resolved = resolve_safe_path(tmp_path, "subdir/file.py")
    assert resolved == subfile.resolve()


def test_resolve_safe_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(PathTraversalError):
        resolve_safe_path(tmp_path, "../../etc/passwd")


def test_has_ntfs_alternate_stream() -> None:
    assert has_ntfs_alternate_stream("file.py:stream")
    assert has_ntfs_alternate_stream("dir/test.txt:$DATA")
    # Windows drive letter should not trigger alternate stream
    if os.name == "nt":
        assert not has_ntfs_alternate_stream("C:\\path\\file.py")


def test_windows_reserved_name() -> None:
    assert is_windows_reserved_name("CON")
    assert is_windows_reserved_name("con.txt")
    assert is_windows_reserved_name("NUL")
    assert is_windows_reserved_name("com1.json")
    assert not is_windows_reserved_name("content.py")


def test_resolve_safe_path_ntfs_stream_rejected(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedPathError):
        resolve_safe_path(tmp_path, "secret.py:hidden")


def test_resolve_safe_path_null_byte_rejected(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedPathError):
        resolve_safe_path(tmp_path, "file.py\0.txt")
