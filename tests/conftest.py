"""Pytest test configuration and fixtures."""

import sys
from pathlib import Path

import pytest

# Ensure src and repo root are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


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
