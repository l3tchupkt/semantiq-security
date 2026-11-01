"""Data contracts and models for specialized investigation workers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from semantiq.graph.graph import SemanticProgramGraph
from semantiq.models import CodeEvidence, Finding, ProofGap
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.storage.sqlite import SQLiteStorage


class WorkerRole(str, Enum):
    """Specialized investigation worker roles."""

    DISCOVERY = "discovery"
    DATAFLOW = "dataflow"
    AUTHORIZATION = "authorization"
    ADVERSARIAL_VERIFICATION = "adversarial_verification"


class PacketStatus(str, Enum):
    """Lifecycle state of an investigation packet."""

    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PacketBudget:
    """Resource bounds for an individual investigation packet."""

    max_turns: int = 5
    max_tokens: int = 15000
    timeout_seconds: float = 60.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_turns": self.max_turns,
            "max_tokens": self.max_tokens,
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PacketBudget:
        return cls(
            max_turns=int(data.get("max_turns", 5)),
            max_tokens=int(data.get("max_tokens", 15000)),
            timeout_seconds=float(data.get("timeout_seconds", 60.0)),
        )


@dataclass
class InvestigationPacket:
    """Bounded, prioritized packet representing a connected attack surface or subsystem."""

    packet_id: str
    title: str
    description: str
    focus_category: str
    priority: int  # 1 to 10 (10 highest)
    target_symbols: list[str] = field(default_factory=list)
    entrypoint_ids: list[str] = field(default_factory=list)
    sink_ids: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    budget: PacketBudget = field(default_factory=PacketBudget)
    status: PacketStatus = PacketStatus.PENDING
    assigned_worker_id: str | None = None
    retry_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "title": self.title,
            "description": self.description,
            "focus_category": self.focus_category,
            "priority": self.priority,
            "target_symbols": self.target_symbols,
            "entrypoint_ids": self.entrypoint_ids,
            "sink_ids": self.sink_ids,
            "file_paths": self.file_paths,
            "budget": self.budget.to_dict(),
            "status": self.status.value,
            "assigned_worker_id": self.assigned_worker_id,
            "retry_count": self.retry_count,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationPacket:
        return cls(
            packet_id=data["packet_id"],
            title=data.get("title", ""),
            description=data.get("description", ""),
            focus_category=data.get("focus_category", "general"),
            priority=int(data.get("priority", 5)),
            target_symbols=list(data.get("target_symbols", [])),
            entrypoint_ids=list(data.get("entrypoint_ids", [])),
            sink_ids=list(data.get("sink_ids", [])),
            file_paths=list(data.get("file_paths", [])),
            budget=PacketBudget.from_dict(data.get("budget", {})),
            status=PacketStatus(data.get("status", PacketStatus.PENDING.value)),
            assigned_worker_id=data.get("assigned_worker_id"),
            retry_count=int(data.get("retry_count", 0)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class InvestigationHypothesis:
    """Hypothesis formed and tracked by workers."""

    hypothesis_id: str
    packet_id: str
    worker_id: str
    title: str
    description: str
    target_entrypoint: str | None = None
    target_sink: str | None = None
    target_file: str = ""
    target_line: int | None = None
    category: str = "general"
    severity: str = "medium"
    confidence: str = "medium"
    supporting_evidence_ids: list[str] = field(default_factory=list)
    contradictory_evidence: list[str] = field(default_factory=list)
    proof_gaps: list[str] = field(default_factory=list)
    status: str = "proposed"  # proposed, investigating, confirmed, disproven, uncertain

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "packet_id": self.packet_id,
            "worker_id": self.worker_id,
            "title": self.title,
            "description": self.description,
            "target_entrypoint": self.target_entrypoint,
            "target_sink": self.target_sink,
            "target_file": self.target_file,
            "target_line": self.target_line,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "supporting_evidence_ids": self.supporting_evidence_ids,
            "contradictory_evidence": self.contradictory_evidence,
            "proof_gaps": self.proof_gaps,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationHypothesis:
        return cls(
            hypothesis_id=data["hypothesis_id"],
            packet_id=data.get("packet_id", ""),
            worker_id=data.get("worker_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            target_entrypoint=data.get("target_entrypoint"),
            target_sink=data.get("target_sink"),
            target_file=data.get("target_file", ""),
            target_line=data.get("target_line"),
            category=data.get("category", "general"),
            severity=data.get("severity", "medium"),
            confidence=data.get("confidence", "medium"),
            supporting_evidence_ids=list(data.get("supporting_evidence_ids", [])),
            contradictory_evidence=list(data.get("contradictory_evidence", [])),
            proof_gaps=list(data.get("proof_gaps", [])),
            status=data.get("status", "proposed"),
        )


@dataclass
class WorkerOutput:
    """Complete output artifact returned by a specialized worker."""

    worker_id: str
    worker_role: WorkerRole
    packet_id: str
    hypotheses: list[InvestigationHypothesis] = field(default_factory=list)
    candidate_findings: list[Finding] = field(default_factory=list)
    code_evidence: list[CodeEvidence] = field(default_factory=list)
    graph_paths_used: list[dict[str, Any]] = field(default_factory=list)
    queries_performed: list[str] = field(default_factory=list)
    proof_gaps: list[ProofGap] = field(default_factory=list)
    unresolved_sites: list[dict[str, Any]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    total_tokens: int = 0
    duration_seconds: float = 0.0
    is_successful: bool = True
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "worker_role": self.worker_role.value,
            "packet_id": self.packet_id,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "candidate_findings": [f.model_dump() for f in self.candidate_findings],
            "code_evidence": [e.model_dump() for e in self.code_evidence],
            "graph_paths_used": self.graph_paths_used,
            "queries_performed": self.queries_performed,
            "proof_gaps": [g.model_dump() for g in self.proof_gaps],
            "unresolved_sites": self.unresolved_sites,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "total_tokens": self.total_tokens,
            "duration_seconds": round(self.duration_seconds, 3),
            "is_successful": self.is_successful,
            "error_message": self.error_message,
        }


@dataclass
class InvestigationContext:
    """Immutable repository-level context shared across worker instances."""

    repository_root: Path
    source_revision: str
    graph: SemanticProgramGraph
    intelligence: RepositoryIntelligence
    storage: SQLiteStorage
    run_id: str
    scan_id: str

