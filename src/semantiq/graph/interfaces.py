"""Language-neutral protocols and data models for semantic navigation and interprocedural analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from semantiq.graph.models import EdgeKind, NodeKind, RelationshipProvenance


class ResolutionConfidence(float, Enum):
    """Categorical confidence scores for call and dataflow resolutions."""

    DEFINITE = 1.0
    HIGH = 0.9
    MEDIUM = 0.7
    PROBABLE = 0.5
    LOW = 0.3
    UNRESOLVED = 0.1


class AuthGuardKind(str, Enum):
    """Category of security guard protecting an execution path."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ROLE_CHECK = "role_check"
    TENANT_ISOLATION = "tenant_isolation"
    CSRF_PROTECTION = "csrf_protection"
    INPUT_VALIDATION = "input_validation"
    RATE_LIMIT = "rate_limit"


class GuardStatus(str, Enum):
    """Status of a discovered security control along an execution path."""

    ENFORCED = "enforced"
    BYPASSED = "bypassed"
    UNRESOLVED = "unresolved"
    CONDITIONALLY_SKIPPED = "conditionally_skipped"


@dataclass(frozen=True)
class SourceLocation:
    """Exact source coordinates for a symbol, callsite, or syntactic element."""

    file_path: str
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_col": self.start_col,
            "end_col": self.end_col,
        }


@dataclass
class SymbolIdentity:
    """Language-neutral identity and characteristics of a code symbol."""

    symbol_id: str
    name: str
    qualified_name: str
    kind: NodeKind
    location: SourceLocation
    language: str
    is_exported: bool = True
    container_symbol: str | None = None
    parameters: list[str] = field(default_factory=list)
    parameter_defaults: dict[str, str] = field(default_factory=dict)
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None
    base_classes: list[str] = field(default_factory=list)
    mro: list[str] = field(default_factory=list)
    provenance: RelationshipProvenance = RelationshipProvenance.DIRECT_FACT

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "kind": self.kind.value,
            "location": self.location.to_dict(),
            "language": self.language,
            "is_exported": self.is_exported,
            "container_symbol": self.container_symbol,
            "parameters": self.parameters,
            "parameter_defaults": self.parameter_defaults,
            "decorators": self.decorators,
            "docstring": self.docstring,
            "base_classes": self.base_classes,
            "mro": self.mro,
            "provenance": self.provenance.value,
        }


@dataclass
class ArgumentMapping:
    """Mapping of an argument at a callsite to a parameter in the target function."""

    arg_index: int
    arg_name: str | None
    arg_expression: str
    param_name: str | None
    param_index: int | None
    is_variadic: bool = False
    is_keyword: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "arg_index": self.arg_index,
            "arg_name": self.arg_name,
            "arg_expression": self.arg_expression,
            "param_name": self.param_name,
            "param_index": self.param_index,
            "is_variadic": self.is_variadic,
            "is_keyword": self.is_keyword,
        }


@dataclass
class CallRelationship:
    """Interprocedural call from caller to callee with argument mapping and confidence."""

    caller_id: str
    caller_symbol: str
    callee_id: str
    callee_name: str
    call_site: SourceLocation
    call_expression: str
    argument_mappings: list[ArgumentMapping] = field(default_factory=list)
    is_dynamic: bool = False
    dynamic_reason: str | None = None
    provenance: RelationshipProvenance = RelationshipProvenance.STATICALLY_RESOLVED
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "caller_symbol": self.caller_symbol,
            "callee_id": self.callee_id,
            "callee_name": self.callee_name,
            "call_site": self.call_site.to_dict(),
            "call_expression": self.call_expression,
            "argument_mappings": [m.to_dict() for m in self.argument_mappings],
            "is_dynamic": self.is_dynamic,
            "dynamic_reason": self.dynamic_reason,
            "provenance": self.provenance.value,
            "confidence": self.confidence,
        }


@dataclass
class DataflowRelationship:
    """Directional propagation of data/taint between two locations."""

    source_id: str
    source_label: str
    source_location: SourceLocation
    target_id: str
    target_label: str
    target_location: SourceLocation
    edge_kind: EdgeKind
    transformation: str | None = None
    sanitizer_applied: str | None = None
    provenance: RelationshipProvenance = RelationshipProvenance.STATICALLY_RESOLVED
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_label": self.source_label,
            "source_location": self.source_location.to_dict(),
            "target_id": self.target_id,
            "target_label": self.target_label,
            "target_location": self.target_location.to_dict(),
            "edge_kind": self.edge_kind.value,
            "transformation": self.transformation,
            "sanitizer_applied": self.sanitizer_applied,
            "provenance": self.provenance.value,
            "confidence": self.confidence,
        }


@dataclass
class InputBinding:
    """Request-controlled input bound to a handler or parameter."""

    param_name: str
    input_source_kind: str  # "query_param", "path_param", "body", "header", "cookie", "file"
    expression: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "param_name": self.param_name,
            "input_source_kind": self.input_source_kind,
            "expression": self.expression,
            "line": self.line,
        }


@dataclass
class AuthGuardBinding:
    """Security check or guard protecting an entrypoint or handler."""

    guard_name: str
    guard_kind: AuthGuardKind
    status: GuardStatus
    location: SourceLocation
    mechanism: str  # "decorator", "middleware", "dependency_injection", "imperative_check"
    required_roles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "guard_name": self.guard_name,
            "guard_kind": self.guard_kind.value,
            "status": self.status.value,
            "location": self.location.to_dict(),
            "mechanism": self.mechanism,
            "required_roles": self.required_roles,
        }


@dataclass
class FrameworkEntrypoint:
    """A framework-aware HTTP route, WebSocket, or API entrypoint."""

    entrypoint_id: str
    framework_name: str  # "bottle", "flask", "fastapi", "django", "tornado"
    route_path: str
    http_methods: list[str]
    handler_symbol: str
    handler_qualified_name: str
    location: SourceLocation
    input_bindings: list[InputBinding] = field(default_factory=list)
    auth_guards: list[AuthGuardBinding] = field(default_factory=list)
    csrf_protected: bool | None = None
    is_websocket: bool = False
    provenance: RelationshipProvenance = RelationshipProvenance.FRAMEWORK_RESOLVED
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entrypoint_id": self.entrypoint_id,
            "framework_name": self.framework_name,
            "route_path": self.route_path,
            "http_methods": self.http_methods,
            "handler_symbol": self.handler_symbol,
            "handler_qualified_name": self.handler_qualified_name,
            "location": self.location.to_dict(),
            "input_bindings": [b.to_dict() for b in self.input_bindings],
            "auth_guards": [g.to_dict() for g in self.auth_guards],
            "csrf_protected": self.csrf_protected,
            "is_websocket": self.is_websocket,
            "provenance": self.provenance.value,
            "confidence": self.confidence,
        }


@runtime_checkable
class LanguageSemanticEngine(Protocol):
    """Protocol implemented by language-specific semantic engines (Python, TypeScript, etc.)."""

    @property
    def language_id(self) -> str:
        ...

    def resolve_symbol(self, qualified_name: str) -> SymbolIdentity | None:
        ...

    def get_callers(self, symbol_id: str) -> list[CallRelationship]:
        ...

    def get_callees(self, symbol_id: str) -> list[CallRelationship]:
        ...

    def extract_entrypoints(self) -> list[FrameworkEntrypoint]:
        ...

