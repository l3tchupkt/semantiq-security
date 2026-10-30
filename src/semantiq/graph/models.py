"""Typed models and schemas for the Semantic Program Graph (SPG)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NodeKind(str, Enum):
    """Classification of nodes within the Semantic Program Graph."""

    # Structural hierarchy
    REPOSITORY = "repository"
    PACKAGE = "package"
    MODULE = "module"
    FILE = "file"

    # Code structures
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    CALL_SITE = "call_site"

    # Application entry points & handlers
    ROUTE = "route"
    REQUEST_HANDLER = "request_handler"
    MIDDLEWARE = "middleware"
    EVENT_CONSUMER = "event_consumer"
    MESSAGE_PRODUCER = "message_producer"
    ASYNC_QUEUE = "async_queue"

    # Dataflow entities
    PARAMETER = "parameter"
    VARIABLE = "variable"
    EXPRESSION = "expression"
    RETURN_VALUE = "return_value"

    # Data access & persistence
    DATABASE_MODEL = "database_model"
    QUERY = "query"
    DATA_ACCESS = "data_access"

    # External interactions & dangerous operations
    EXTERNAL_REQUEST = "external_request"
    FILE_OPERATION = "file_operation"
    PROCESS_EXEC = "process_exec"
    SENSITIVE_SINK = "sensitive_sink"

    # Security controls & sanitization
    AUTH_CONTROL = "auth_control"
    AUTHORIZATION_CHECK = "authorization_check"
    VALIDATION = "validation"
    SANITIZER = "sanitizer"

    # Context & boundaries
    TRUST_BOUNDARY = "trust_boundary"
    SENSITIVE_RESOURCE = "sensitive_resource"
    TENANT_CONTEXT = "tenant_context"

    # Reasoning, hypotheses & findings
    VULNERABILITY_HYPOTHESIS = "vulnerability_hypothesis"
    EVIDENCE_ITEM = "evidence_item"
    FINDING = "finding"
    VALIDATION_RESULT = "validation_result"


class EdgeKind(str, Enum):
    """Typed relationships connecting Semantic Program Graph nodes."""

    IMPORTS = "imports"
    DEFINES = "defines"
    CALLS = "calls"
    PASSES_ARGUMENT = "passes_argument"
    RETURNS_TO = "returns_to"
    DATA_FLOWS_TO = "data_flows_to"
    CONTROLS_FLOW = "controls_flow"
    REACHES = "reaches"
    AUTHENTICATES = "authenticates"
    AUTHORIZES = "authorizes"
    VALIDATES = "validates"
    SANITIZES = "sanitizes"
    QUERIES = "queries"
    ACCESSES_RESOURCE = "accesses_resource"
    CONTROLS_TENANT = "controls_tenant"
    TRANSITIONS_STATE = "transitions_state"
    CROSSES_BOUNDARY = "crosses_boundary"
    MITIGATES = "mitigates"
    PUBLISHES_TO = "publishes_to"
    CONSUMES_FROM = "consumes_from"
    DISPATCHES_ASYNC = "dispatches_async"
    PROPAGATES_PAYLOAD = "propagates_payload"


class RelationshipProvenance(str, Enum):
    """Provenance and epistemological grounding of a graph node or edge."""

    DIRECT_FACT = "direct_fact"  # Extracted directly from AST or source syntax
    STATICALLY_INFERRED = "statically_inferred"  # Inferred via static call/import resolution
    UNRESOLVED = "unresolved"  # Dynamic dispatch or unresolvable reference
    MODEL_PROPOSED = "model_proposed"  # Suggested by AI assistant, requiring local verification
    FRAMEWORK_RESOLVED = "framework_resolved"  # Resolved via framework queue or task name conventions
    PROBABLE_UNVERIFIED = "probable_unverified"  # Heuristically matched queue/schema without explicit binding


class GraphNode(BaseModel):
    """A versioned, typed node within the Semantic Program Graph."""

    model_config = ConfigDict(frozen=True)

    id: str  # Stable global identifier
    kind: NodeKind
    label: str
    file_path: str
    start_line: int
    end_line: int
    provenance: RelationshipProvenance = RelationshipProvenance.DIRECT_FACT
    source_revision: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """A typed, directed edge connecting two Semantic Program Graph nodes."""

    model_config = ConfigDict(frozen=True)

    source_id: str
    target_id: str
    kind: EdgeKind
    provenance: RelationshipProvenance = RelationshipProvenance.DIRECT_FACT
    confidence: float = 1.0  # 0.0 to 1.0
    properties: dict[str, Any] = Field(default_factory=dict)
