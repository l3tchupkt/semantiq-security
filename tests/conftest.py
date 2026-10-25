"""Pytest test configuration and fixtures."""

import sys
from pathlib import Path

import pytest

# Ensure src is on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to tests/fixtures directory."""
    return Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def vulnerable_app_dir(fixtures_dir: Path) -> Path:
    """Return path to vulnerable test fixture directory."""
    return fixtures_dir / "vulnerable_app"


@pytest.fixture
def safe_app_dir(fixtures_dir: Path) -> Path:
    """Return path to safe test fixture directory."""
    return fixtures_dir / "safe_app"
