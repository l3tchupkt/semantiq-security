"""Investigation Packet Model & Lifecycle State Machine for Deep Scan Orchestration.

Defines the contract, dimensions, retry policy, and auditable state transitions
governing units of investigation work.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from semantiq.skills.contract import SkillBudget, SkillPermission


class PacketStatus(str, Enum):
    """Auditable states of an investigation packet."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    RETRY_PENDING = "retry_pending"
    CANCELLED = "cancelled"


class PacketDimension(str, Enum):
    """Architectural dimension targeted by an investigation packet."""

    ENTRYPOINT_ROUTE = "entrypoint_route"
    CLI_COMMAND = "cli_command"
    SENSITIVE_SINK = "sensitive_sink"
    AUTH_BOUNDARY = "auth_boundary"
    TENANT_ISOLATION = "tenant_isolation"
    ASYNC_QUEUE = "async_queue"
    FILE_RESOURCE = "file_resource"
    EXTERNAL_DEPENDENCY = "external_dependency"
    UNRESOLVED_DISPATCH = "unresolved_dispatch"
    UNCOVERED_GRAPH_REGION = "uncovered_graph_region"


# Valid state machine transitions
ALLOWED_TRANSITIONS: dict[PacketStatus, set[PacketStatus]] = {
    PacketStatus.PENDING: {
        PacketStatus.READY,
        PacketStatus.RUNNING,
        PacketStatus.CANCELLED,
        PacketStatus.FAILED,
    },
    PacketStatus.READY: {
        PacketStatus.RUNNING,
        PacketStatus.CANCELLED,
        PacketStatus.FAILED,
    },
    PacketStatus.RUNNING: {
        PacketStatus.COMPLETED,
        PacketStatus.PARTIALLY_COMPLETED,
        PacketStatus.TIMED_OUT,
        PacketStatus.FAILED,
        PacketStatus.CANCELLED,
    },
    PacketStatus.TIMED_OUT: {
        PacketStatus.RETRY_PENDING,
        PacketStatus.FAILED,
        PacketStatus.CANCELLED,
    },
    PacketStatus.FAILED: {
        PacketStatus.RETRY_PENDING,
        PacketStatus.CANCELLED,
    },
    PacketStatus.RETRY_PENDING: {
        PacketStatus.READY,
        PacketStatus.RUNNING,
        PacketStatus.CANCELLED,
        PacketStatus.FAILED,
    },
    PacketStatus.PARTIALLY_COMPLETED: {
        PacketStatus.COMPLETED,
        PacketStatus.CANCELLED,
    },
    PacketStatus.COMPLETED: set(),  # Terminal
    PacketStatus.CANCELLED: set(),  # Terminal
}


class RetryPolicy(BaseModel):
    """Exponential backoff and jitter policy for transient worker failures."""

    max_retries: int = Field(default=3, ge=0)
    backoff_base_seconds: float = Field(default=1.0, ge=0.1)
    max_backoff_seconds: float = Field(default=30.0, ge=1.0)
    jitter_factor: float = Field(default=0.2, ge=0.0, le=1.0)
    retryable_error_codes: list[str] = Field(
        default_factory=lambda: [
            "transient_error",
            "rate_limit",
            "rate limit",
            "lock_timeout",
            "connection_reset",
            "temporary_unavailable",
            "timeout",
        ]
    )

    def is_retryable(self, error: Exception | str) -> bool:
        """Evaluate whether a failure reason or exception is eligible for retry."""
        err_msg = str(error).lower()
        # Never retry permanent validation or schema errors
        if any(
            term in err_msg
            for term in ["validationerror", "syntaxerror", "permissiondenied", "pydantic"]
        ):
            return False
        return any(code in err_msg for code in self.retryable_error_codes)

    def calculate_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay with uniform random jitter."""
        if attempt <= 0:
            return 0.0
        exp_delay = min(self.max_backoff_seconds, self.backoff_base_seconds * (2 ** (attempt - 1)))
        jitter = exp_delay * self.jitter_factor * (random.uniform(-1.0, 1.0))
        return float(max(0.0, exp_delay + jitter))


class PacketStateTransition(BaseModel):
    """Audit record capturing an auditable change in packet status."""

    transition_id: str = Field(default_factory=lambda: f"trans_{uuid.uuid4().hex[:10]}")
    packet_id: str
    from_state: PacketStatus
    to_state: PacketStatus
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reason: str = Field(default="")


class InvestigationPacket(BaseModel):
    """Strongly-typed unit of security investigation work."""

    packet_id: str
    scan_id: str
    repository_root: Path
    source_revision: str
    dimension: PacketDimension
    objective: str
    target_symbols: list[str] = Field(default_factory=list)
    target_files: list[str] = Field(default_factory=list)
    relevant_node_ids: list[str] = Field(default_factory=list)
    relevant_edge_ids: list[str] = Field(default_factory=list)
    assigned_skills: list[str] = Field(default_factory=list)
    required_context: dict[str, Any] = Field(default_factory=dict)
    excluded_regions: list[str] = Field(default_factory=list)
    permission_ceiling: list[SkillPermission] = Field(
        default_factory=lambda: [SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY]
    )
    budget: SkillBudget = Field(default_factory=SkillBudget)
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    completion_criteria: str = Field(default="")
    parent_packet_id: str | None = None
    state: PacketStatus = Field(default=PacketStatus.PENDING)
    retry_count: int = Field(default=0)
    transitions: list[PacketStateTransition] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def create(
        cls,
        scan_id: str,
        repository_root: Path,
        source_revision: str,
        dimension: PacketDimension,
        objective: str,
        target_symbols: list[str] | None = None,
        target_files: list[str] | None = None,
        relevant_node_ids: list[str] | None = None,
        assigned_skills: list[str] | None = None,
        permission_ceiling: list[SkillPermission] | None = None,
        budget: SkillBudget | None = None,
        retry_policy: RetryPolicy | None = None,
        parent_packet_id: str | None = None,
    ) -> InvestigationPacket:
        """Factory constructor generating a deterministic, stable packet identifier."""
        symbols = sorted(target_symbols or [])
        files = sorted(target_files or [])
        nodes = sorted(relevant_node_ids or [])
        seed = f"{dimension.value}:{source_revision}:{','.join(symbols)}:{','.join(files)}:{','.join(nodes)}"
        packet_id = f"pkt_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"

        packet = cls(
            packet_id=packet_id,
            scan_id=scan_id,
            repository_root=repository_root,
            source_revision=source_revision,
            dimension=dimension,
            objective=objective,
            target_symbols=symbols,
            target_files=files,
            relevant_node_ids=nodes,
            assigned_skills=assigned_skills or [],
            permission_ceiling=permission_ceiling
            or [SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
            budget=budget or SkillBudget(),
            retry_policy=retry_policy or RetryPolicy(),
            parent_packet_id=parent_packet_id,
            state=PacketStatus.PENDING,
        )
        # Record initial transition to PENDING
        initial_trans = PacketStateTransition(
            packet_id=packet_id,
            from_state=PacketStatus.PENDING,
            to_state=PacketStatus.PENDING,
            reason="Packet created",
        )
        packet.transitions.append(initial_trans)
        return packet

    def transition_to(self, new_state: PacketStatus, reason: str = "") -> PacketStateTransition:
        """Validate and record an auditable state transition."""
        allowed = ALLOWED_TRANSITIONS.get(self.state, set())
        if new_state != self.state and new_state not in allowed:
            raise ValueError(
                f"Invalid packet state transition: cannot transition packet {self.packet_id} "
                f"from '{self.state.value}' to '{new_state.value}'."
            )

        transition = PacketStateTransition(
            packet_id=self.packet_id,
            from_state=self.state,
            to_state=new_state,
            reason=reason,
        )
        self.state = new_state
        self.transitions.append(transition)
        return transition
