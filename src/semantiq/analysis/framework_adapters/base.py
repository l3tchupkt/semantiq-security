"""Base class and common models for framework-specific route and entrypoint adapters."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod

from semantiq.graph.interfaces import (
    AuthGuardBinding,
    FrameworkEntrypoint,
    InputBinding,
    SourceLocation,
)


class FrameworkAdapter(ABC):
    """Abstract interface for extracting framework-specific routes, inputs, and security guards."""

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Name of the web/API framework (e.g. 'bottle', 'flask', 'fastapi', 'django', 'tornado')."""
        ...

    @abstractmethod
    def detect_entrypoints(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: list[str],
    ) -> list[FrameworkEntrypoint]:
        """Extract HTTP/WebSocket entrypoints declared via this framework."""
        ...

    @abstractmethod
    def detect_auth_guards(
        self,
        node: ast.AST,
        file_path: str,
    ) -> list[AuthGuardBinding]:
        """Detect authentication, authorization, and tenant isolation guards."""
        ...

    @abstractmethod
    def detect_inputs(
        self,
        node: ast.AST,
    ) -> list[InputBinding]:
        """Detect request-controlled inputs accessed within a handler or statement."""
        ...

    def get_source_location(self, node: ast.AST, file_path: str) -> SourceLocation:
        """Helper to create a SourceLocation from an AST node."""
        lineno = getattr(node, "lineno", 1)
        end_lineno = getattr(node, "end_lineno", lineno)
        col_offset = getattr(node, "col_offset", 0)
        end_col_offset = getattr(node, "end_col_offset", 0)
        return SourceLocation(
            file_path=file_path.replace("\\", "/"),
            start_line=lineno,
            end_line=end_lineno,
            start_col=col_offset,
            end_col=end_col_offset,
        )

