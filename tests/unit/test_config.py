"""Unit tests for configuration loading and validation."""

from pathlib import Path

from semantiq.config import SemantiqConfig


def test_default_config() -> None:
    cfg = SemantiqConfig()
    assert cfg.scan.mode == "standard"
    assert cfg.validation.allow_execution is False
    assert cfg.ai.enabled is False
    assert cfg.scan.max_files == 50000


def test_config_from_dict() -> None:
    data = {
        "scan": {"mode": "deep", "max_files": 100},
        "validation": {"allow_execution": True},
    }
    cfg = SemantiqConfig.from_dict(data)
    assert cfg.scan.mode == "deep"
    assert cfg.scan.max_files == 100
    assert cfg.validation.allow_execution is True


def test_config_from_toml(tmp_path: Path) -> None:
    toml_file = tmp_path / "test_cfg.toml"
    toml_file.write_text(
        """
[scan]
mode = "diff"
max_files = 250
focus = ["sql-injection", "ssrf"]

[validation]
allow_execution = true
""",
        encoding="utf-8",
    )
    cfg = SemantiqConfig.load_from_file(toml_file)
    assert cfg.scan.mode == "diff"
    assert cfg.scan.max_files == 250
    assert cfg.scan.focus == ["sql-injection", "ssrf"]
    assert cfg.validation.allow_execution is True


def test_config_from_env(monkeypatch) -> None:
    monkeypatch.setenv("SEMANTIQ_ALLOW_EXECUTION", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-1234567890123456")
    cfg = SemantiqConfig.from_env()
    assert cfg.validation.allow_execution is True
    assert cfg.ai.enabled is True
    assert cfg.ai.provider == "openai"
    assert cfg.ai.api_key == "test-key-1234567890123456"
