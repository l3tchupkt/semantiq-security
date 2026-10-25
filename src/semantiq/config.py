"""Configuration management for Semantiq Security."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

DEFAULT_EXCLUDE_PATTERNS = [
    "**/.git/**",
    "**/.svn/**",
    "**/.hg/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/env/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/dist/**",
    "**/build/**",
    "**/.eggs/**",
    "**/*.egg-info/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
    "**/.tox/**",
    "**/.coverage",
    "**/htmlcov/**",
    "**/.idea/**",
    "**/.vscode/**",
    "**/*.min.js",
    "**/*.bundle.js",
]


class ScanConfig(BaseModel):
    """Scan and file inventory configuration."""
    mode: str = "standard"
    max_file_size_bytes: int = 2 * 1024 * 1024  # 2 MB limit
    max_files: int = 50_000
    include_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS))
    focus: list[str] = Field(default_factory=list)
    scope_paths: list[str] = Field(default_factory=list)


class ValidationConfig(BaseModel):
    """Validation and execution safety configuration."""
    default_mode: str = "static"
    allow_execution: bool = False  # Explicit opt-in required for dynamic execution
    timeout_seconds: int = 30
    max_output_bytes: int = 100 * 1024  # 100 KB max buffer


class AIConfig(BaseModel):
    """AI provider and investigation configuration."""
    enabled: bool = False
    provider: str = "ollama"  # openai, anthropic, ollama, mock
    model: str = "deepseek-r1"
    api_key: str | None = None
    endpoint_url: str | None = None
    temperature: float = 0.0
    timeout_seconds: float = 60.0
    verify_citations: bool = True


class StorageConfig(BaseModel):
    """Storage and SQLite database configuration."""
    database_path: str = "~/.semantiq/semantiq.db"


class SemantiqConfig(BaseModel):
    """Master configuration for Semantiq Security."""
    scan: ScanConfig = Field(default_factory=ScanConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemantiqConfig:
        """Construct configuration from dictionary."""
        return cls(**data)

    @classmethod
    def load_from_file(cls, path: str | Path) -> SemantiqConfig:
        """Load configuration from a TOML or JSON file."""
        file_path = Path(path).expanduser().resolve()
        if not file_path.exists():
            return cls()

        content = file_path.read_text(encoding="utf-8")
        if file_path.suffix.lower() == ".toml":
            import sys
            if sys.version_info >= (3, 11):
                import tomllib
                data = tomllib.loads(content)
            else:
                try:
                    import tomli as tomllib_legacy  # type: ignore[import-not-found]
                    data = tomllib_legacy.loads(content)
                except ImportError:
                    data = {}
            return cls.from_dict(data)
        elif file_path.suffix.lower() == ".json":
            import json
            data = json.loads(content)
            return cls.from_dict(data)
        return cls()

    @classmethod
    def from_env(cls) -> SemantiqConfig:
        """Construct configuration augmented with environment variables."""
        cfg = cls()
        if os.getenv("SEMANTIQ_ALLOW_EXECUTION", "").lower() in ("1", "true", "yes"):
            cfg.validation.allow_execution = True
        if os.getenv("SEMANTIQ_AI_ENABLED", "").lower() in ("1", "true", "yes"):
            cfg.ai.enabled = True
        if api_key := os.getenv("OPENAI_API_KEY"):
            cfg.ai.api_key = api_key
            cfg.ai.provider = "openai"
            cfg.ai.enabled = True
        elif api_key := os.getenv("ANTHROPIC_API_KEY"):
            cfg.ai.api_key = api_key
            cfg.ai.provider = "anthropic"
            cfg.ai.enabled = True
        if db_path := os.getenv("SEMANTIQ_DB_PATH"):
            cfg.storage.database_path = db_path
        return cfg
