"""Integration smoke tests for Semantiq CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from semantiq.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Semantiq Security" in result.output
    assert "Lakshmikanthan K" in result.output


def test_cli_doctor() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Semantiq Security Doctor" in result.output
    assert "Security Configuration" in result.output


def test_cli_inspect(vulnerable_app_dir: Path) -> None:
    result = runner.invoke(app, ["inspect", str(vulnerable_app_dir)])
    assert result.exit_code == 0
    assert "Repository Inspection" in result.output
    assert "Language Distribution" in result.output


def test_cli_scan(vulnerable_app_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(vulnerable_app_dir)])
    assert result.exit_code == 0
    assert "Scan ID:" in result.output
    assert "Total Findings:" in result.output
