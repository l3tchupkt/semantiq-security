"""Semantiq Security exception hierarchy."""

from __future__ import annotations


class SemantiqError(Exception):
    """Base exception for all Semantiq Security errors."""

    def __init__(self, message: str, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class ConfigurationError(SemantiqError):
    """Raised when configuration is missing, invalid, or conflicting."""


class RepositoryError(SemantiqError):
    """Base exception for repository inspection and path handling errors."""


class TargetNotFoundError(RepositoryError):
    """Raised when the specified target repository or path does not exist."""


class PathTraversalError(RepositoryError):
    """Raised when a path attempts directory traversal outside the target repository."""


class SymlinkEscapeError(RepositoryError):
    """Raised when a symbolic link resolves to a path outside the target repository."""


class ScopeViolationError(RepositoryError):
    """Raised when an inspected scope is outside the repository boundaries."""


class UnsupportedPathError(RepositoryError):
    """Raised when a path uses unsupported filesystem constructs (e.g., NTFS alternate data streams or reserved DOS device names)."""


class AnalysisError(SemantiqError):
    """Raised when static analysis or AST parsing fails unexpectedly."""


class ParseError(AnalysisError):
    """Raised when a source file cannot be parsed into an AST."""


class ProviderError(SemantiqError):
    """Base exception for AI provider errors."""


class ProviderAuthenticationError(ProviderError):
    """Raised when AI provider credentials are missing or rejected."""


class ProviderRateLimitError(ProviderError):
    """Raised when an AI provider returns rate limit errors."""


class ProviderTimeoutError(ProviderError):
    """Raised when an AI provider request times out."""


class CitationVerificationError(ProviderError):
    """Raised when an AI model cites nonexistent file paths or line numbers."""


class ValidationError(SemantiqError):
    """Base exception for validation errors."""


class ExecutionNotPermittedError(ValidationError):
    """Raised when dynamic execution is attempted without explicit allow_execution opt-in."""


class SandboxTimeoutError(ValidationError):
    """Raised when a sandboxed execution times out."""


class SandboxResourceError(ValidationError):
    """Raised when a sandboxed process exceeds resource or output limits."""


class RemediationError(SemantiqError):
    """Base exception for remediation and patching errors."""


class PatchApplicationError(RemediationError):
    """Raised when a unified diff cannot be applied cleanly to the target files."""


class StorageError(SemantiqError):
    """Raised when local database operations fail."""
