"""Language frontend protocol and capability models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from semantiq.graph.graph import SemanticProgramGraph


class FrontendCapabilities(BaseModel):
    """Declared capabilities, limitations, and semantic coverage for a language frontend."""

    language_id: str
    parsing_coverage: str
    symbol_resolution_coverage: str
    call_graph_coverage: str
    data_flow_capabilities: str
    framework_semantics: list[str] = Field(default_factory=list)
    unsupported_syntax_notes: list[str] = Field(default_factory=list)


@dataclass
class FrontendResult:
    """Outcome of parsing a source file into the Semantic Program Graph."""

    file_path: str
    language: str
    parsed_successfully: bool
    nodes_created: int = 0
    edges_created: int = 0
    gaps: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class LanguageFrontend(ABC):
    """Abstract interface for language-aware parsing and graph generation."""

    @property
    @abstractmethod
    def language_id(self) -> str:
        """Identifier of the language (e.g. 'python', 'javascript', 'typescript')."""
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> tuple[str, ...]:
        """File extensions handled by this frontend."""
        pass

    @abstractmethod
    def parse_file(
        self,
        file_path: str,
        source_code: str,
        graph: SemanticProgramGraph,
        repo_root: Path,
        source_revision: str = "",
    ) -> FrontendResult:
        """Parse source code, populating the Semantic Program Graph with typed nodes and edges."""
        pass

    @abstractmethod
    def get_capabilities(self) -> FrontendCapabilities:
        """Return the explicit semantic capabilities and limitations of this frontend."""
        pass
