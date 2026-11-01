"""Explicit Security Hypothesis Lifecycle & Information-Value Management.

Implements the formal hypothesis lifecycle for autonomous vulnerability discovery:
  FORMED -> EVIDENCE_SEEKING -> ADVERSARIALLY_CHALLENGED -> CONFIRMED_VULNERABILITY / REFUTED_BY_DEFENSE / INSUFFICIENT_EVIDENCE / ABANDONED

Prioritizes exploration using multi-factor information-value ranking:
  Score = (Impact * 0.40) + (Reachability * 0.30) + (Novelty * 0.20) + (Uncertainty * 0.10)
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from semantiq.models import (
    CodeEvidence,
    ProofGap,
    ProofGapStatus,
    VulnerabilityCategory,
)

logger = logging.getLogger(__name__)


class HypothesisStatus(str, Enum):
    """Formal lifecycle states of an autonomous security hypothesis."""

    FORMED = "FORMED"
    EVIDENCE_SEEKING = "EVIDENCE_SEEKING"
    ADVERSARIALLY_CHALLENGED = "ADVERSARIALLY_CHALLENGED"
    CONFIRMED_VULNERABILITY = "CONFIRMED_VULNERABILITY"
    REFUTED_BY_DEFENSE = "REFUTED_BY_DEFENSE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    ABANDONED = "ABANDONED"


class DeepVulnerabilityClass(str, Enum):
    """The 5 primary vulnerability classes prioritized in autonomous discovery."""

    AUTHORIZATION_ACCESS_CONTROL = "AUTHORIZATION_ACCESS_CONTROL"
    INJECTION_EXECUTION = "INJECTION_EXECUTION"
    ASYNC_DISTRIBUTED_SYSTEMS = "ASYNC_DISTRIBUTED_SYSTEMS"
    AUTHENTICATION_SESSION_SECURITY = "AUTHENTICATION_SESSION_SECURITY"
    FILE_RESOURCE_HANDLING = "FILE_RESOURCE_HANDLING"


class InvestigativeAction(BaseModel):
    """Record of an explicit action executed by the autonomous discovery engine."""

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(default_factory=lambda: "")
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    target_hypothesis_id: str = ""
    result_summary: str = ""
    uncertainty_delta: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def ensure_id(self) -> str:
        """Ensure a unique action identifier."""
        if not self.action_id:
            raw = f"{self.timestamp}:{self.tool_name}:{self.target_hypothesis_id}:{self.rationale[:40]}"
            return f"act_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"
        return self.action_id


class SecurityHypothesis(BaseModel):
    """Structured security hypothesis undergoing autonomous verification."""

    hypothesis_id: str
    title: str
    vuln_class: DeepVulnerabilityClass
    category: VulnerabilityCategory
    cwe_ids: list[str] = Field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.FORMED

    target_symbol: str = ""
    file_path: str = ""
    entry_point: str = ""
    sensitive_sink: str = ""
    threat_scenario: str = ""
    exploit_mechanism: str = ""

    preconditions: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)

    # Multi-factor scoring components (0.0 to 100.0)
    impact_score: float = 50.0
    reachability_score: float = 50.0
    novelty_score: float = 80.0
    uncertainty_score: float = 90.0

    supporting_evidence: list[CodeEvidence] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    proof_gaps: list[ProofGap] = Field(default_factory=list)

    action_history: list[InvestigativeAction] = Field(default_factory=list)
    state_transitions: list[dict[str, Any]] = Field(default_factory=list)

    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def information_value(self) -> float:
        """Calculate composite information value for exploration ranking.

        Score = (Impact * 0.40) + (Reachability * 0.30) + (Novelty * 0.20) + (Uncertainty * 0.10)
        """
        # Active hypotheses have full value; resolved ones lose discovery priority
        terminal_multiplier = 0.05 if self.status in {
            HypothesisStatus.CONFIRMED_VULNERABILITY,
            HypothesisStatus.REFUTED_BY_DEFENSE,
            HypothesisStatus.ABANDONED,
        } else 1.0

        raw_score = (
            (self.impact_score * 0.40)
            + (self.reachability_score * 0.30)
            + (self.novelty_score * 0.20)
            + (self.uncertainty_score * 0.10)
        )
        return round(raw_score * terminal_multiplier, 3)

    def is_active(self) -> bool:
        """Check if hypothesis is still undergoing investigation."""
        return self.status in {
            HypothesisStatus.FORMED,
            HypothesisStatus.EVIDENCE_SEEKING,
            HypothesisStatus.ADVERSARIALLY_CHALLENGED,
        }


class HypothesisManager:
    """Manages collection, ranking, lifecycle transitions, and evidence for hypotheses."""

    def __init__(self) -> None:
        self.hypotheses: dict[str, SecurityHypothesis] = {}
        self.action_log: list[InvestigativeAction] = []
        self._investigated_symbols: set[str] = set()

    def add_hypothesis(self, hypothesis: SecurityHypothesis) -> str:
        """Register a new hypothesis in the manager."""
        if not hypothesis.hypothesis_id:
            raw = f"{hypothesis.vuln_class.value}:{hypothesis.file_path}:{hypothesis.target_symbol}:{hypothesis.title}"
            hypothesis.hypothesis_id = f"hyp_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"

        # Record initial state transition
        if not hypothesis.state_transitions:
            hypothesis.state_transitions.append({
                "from_status": None,
                "to_status": hypothesis.status.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": "Hypothesis formulated from initial threat model / attack surface discovery",
            })

        self.hypotheses[hypothesis.hypothesis_id] = hypothesis
        if hypothesis.target_symbol:
            self._investigated_symbols.add(hypothesis.target_symbol)
        return hypothesis.hypothesis_id

    def get_hypothesis(self, hypothesis_id: str) -> SecurityHypothesis | None:
        """Lookup hypothesis by ID."""
        return self.hypotheses.get(hypothesis_id)

    def rank_hypotheses(
        self,
        active_only: bool = False,
        statuses: list[HypothesisStatus] | None = None,
    ) -> list[SecurityHypothesis]:
        """Rank hypotheses by information value in descending order."""
        hyps = list(self.hypotheses.values())
        if active_only:
            hyps = [h for h in hyps if h.is_active()]
        elif statuses:
            hyps = [h for h in hyps if h.status in statuses]

        return sorted(hyps, key=lambda h: h.information_value, reverse=True)

    def transition_state(
        self,
        hypothesis_id: str,
        new_status: HypothesisStatus,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecurityHypothesis:
        """Execute a valid lifecycle state transition with audit log."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            raise KeyError(f"Hypothesis {hypothesis_id} not found.")

        old_status = hyp.status
        hyp.status = new_status
        hyp.updated_at = datetime.now(timezone.utc).isoformat()

        # Update uncertainty score based on transition
        if new_status in {HypothesisStatus.CONFIRMED_VULNERABILITY, HypothesisStatus.REFUTED_BY_DEFENSE}:
            hyp.uncertainty_score = 0.0
        elif new_status == HypothesisStatus.ADVERSARIALLY_CHALLENGED:
            hyp.uncertainty_score = max(20.0, hyp.uncertainty_score - 30.0)
        elif new_status == HypothesisStatus.EVIDENCE_SEEKING:
            hyp.uncertainty_score = max(40.0, hyp.uncertainty_score - 10.0)

        transition_entry = {
            "from_status": old_status.value,
            "to_status": new_status.value,
            "timestamp": hyp.updated_at,
            "reason": reason,
            "metadata": metadata or {},
        }
        hyp.state_transitions.append(transition_entry)
        logger.info(
            "Hypothesis %s transitioned from %s to %s: %s",
            hypothesis_id,
            old_status.value,
            new_status.value,
            reason,
        )
        return hyp

    def add_evidence(self, hypothesis_id: str, evidence: CodeEvidence) -> None:
        """Attach verified or candidate code evidence to a hypothesis."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return

        evidence.ensure_id()
        # Avoid duplicate evidence
        existing_ids = {e.evidence_id for e in hyp.supporting_evidence}
        if evidence.evidence_id not in existing_ids:
            hyp.supporting_evidence.append(evidence)
            hyp.updated_at = datetime.now(timezone.utc).isoformat()
            # Reducing uncertainty as concrete evidence arrives
            hyp.uncertainty_score = max(10.0, hyp.uncertainty_score - 15.0)

    def add_counterevidence(self, hypothesis_id: str, note: str) -> None:
        """Record defensive counterevidence against a hypothesis."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return
        if note not in hyp.counterevidence:
            hyp.counterevidence.append(note)
            hyp.updated_at = datetime.now(timezone.utc).isoformat()

    def add_proof_gap(self, hypothesis_id: str, gap: ProofGap) -> None:
        """Attach an open proof gap to a hypothesis."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return
        gap.ensure_id()
        existing = {g.gap_id for g in hyp.proof_gaps}
        if gap.gap_id not in existing:
            hyp.proof_gaps.append(gap)
            hyp.updated_at = datetime.now(timezone.utc).isoformat()
            # Open proof gaps slightly increase uncertainty
            hyp.uncertainty_score = min(100.0, hyp.uncertainty_score + 10.0)

    def resolve_proof_gap(self, hypothesis_id: str, gap_id: str, resolution_notes: str) -> None:
        """Mark a proof gap as resolved."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return
        for gap in hyp.proof_gaps:
            if gap.gap_id == gap_id:
                gap.status = ProofGapStatus.RESOLVED
                gap.resolution_criteria = resolution_notes
                hyp.updated_at = datetime.now(timezone.utc).isoformat()
                hyp.uncertainty_score = max(5.0, hyp.uncertainty_score - 15.0)
                break

    def record_action(self, hypothesis_id: str, action: InvestigativeAction) -> None:
        """Record an investigative action taken towards resolving a hypothesis."""
        hyp = self.hypotheses.get(hypothesis_id)
        action_with_id = action.model_copy(update={"action_id": action.ensure_id(), "target_hypothesis_id": hypothesis_id})
        self.action_log.append(action_with_id)
        if hyp:
            hyp.action_history.append(action_with_id)
            if action.uncertainty_delta > 0:
                hyp.uncertainty_score = max(0.0, hyp.uncertainty_score - action.uncertainty_delta)

    def select_next_action(
        self,
        hypothesis_id: str,
    ) -> tuple[str, dict[str, Any], str]:
        """Determine the next investigative tool call and rationale to minimize uncertainty."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp or not hyp.is_active():
            return "semantiq_inspect_repository", {}, "Default baseline repository inspection."

        # Case 1: Initial Formed state -> Seek Entrypoint and Reachability
        if hyp.status == HypothesisStatus.FORMED:
            if hyp.entry_point and not hyp.supporting_evidence:
                return (
                    "semantiq_query_dataflow_path",
                    {"source_symbol": hyp.entry_point, "sink_category": hyp.category.value, "max_depth": 8},
                    f"Tracing reachability and dataflow from entrypoint '{hyp.entry_point}' to sink '{hyp.sensitive_sink}'.",
                )
            if hyp.target_symbol:
                return (
                    "semantiq_query_callers_callees",
                    {"symbol_name": hyp.target_symbol, "direction": "callers"},
                    f"Inspecting callers of target symbol '{hyp.target_symbol}' to verify external reachability.",
                )
            return (
                "semantiq_query_symbols",
                {"query": hyp.title.split()[0], "kind": "function"},
                f"Locating symbols matching hypothesis title '{hyp.title}'.",
            )

        # Case 2: In Evidence Seeking state -> Trace arguments, callers, and sensitive operations
        if hyp.status == HypothesisStatus.EVIDENCE_SEEKING:
            # Check if we need interprocedural propagation evidence
            has_propagation = any(getattr(e, "role", "") == "propagation" for e in hyp.supporting_evidence)
            if not has_propagation and hyp.target_symbol:
                return (
                    "semantiq_query_dataflow_path",
                    {"source_symbol": hyp.target_symbol, "sink_category": hyp.category.value},
                    f"Seeking interprocedural propagation path connecting '{hyp.target_symbol}' to sink.",
                )
            return (
                "semantiq_query_route_reachability",
                {"sink_kind": hyp.sensitive_sink or "process_exec"},
                f"Verifying HTTP route reachability to sensitive sink '{hyp.sensitive_sink}'.",
            )

        # Case 3: Adversarially Challenged state -> Actively search for sanitizers, guards, auth checks
        if hyp.status == HypothesisStatus.ADVERSARIALLY_CHALLENGED:
            if hyp.vuln_class == DeepVulnerabilityClass.AUTHORIZATION_ACCESS_CONTROL:
                return (
                    "semantiq_query_authorization_boundary",
                    {"route_path": hyp.entry_point},
                    f"Checking for route-level authentication decorators or tenant ownership checks on '{hyp.entry_point}'.",
                )
            if hyp.vuln_class == DeepVulnerabilityClass.FILE_RESOURCE_HANDLING:
                return (
                    "semantiq_identify_authorization_checks",
                    {"target_symbol": hyp.target_symbol},
                    f"Searching for path normalization, is_relative_to, or containment assertions in '{hyp.target_symbol}'.",
                )
            return (
                "semantiq_query_symbols",
                {"query": "sanitize", "kind": "function"},
                f"Searching for sanitization routines applied between entrypoint '{hyp.entry_point}' and sink '{hyp.sensitive_sink}'.",
            )

        return "semantiq_get_repository_overview", {}, "Exploration complete for hypothesis."

    def get_summary(self) -> dict[str, Any]:
        """Generate high-level metrics of current hypothesis state."""
        total = len(self.hypotheses)
        by_status = {s.value: 0 for s in HypothesisStatus}
        by_class = {c.value: 0 for c in DeepVulnerabilityClass}
        total_open_gaps = 0

        for h in self.hypotheses.values():
            by_status[h.status.value] += 1
            by_class[h.vuln_class.value] += 1
            total_open_gaps += sum(1 for g in h.proof_gaps if g.status == ProofGapStatus.OPEN)

        active_count = sum(1 for h in self.hypotheses.values() if h.is_active())
        avg_uncertainty = (
            sum(h.uncertainty_score for h in self.hypotheses.values()) / total
            if total > 0
            else 0.0
        )

        top_hyps = [
            {
                "hypothesis_id": h.hypothesis_id,
                "title": h.title,
                "class": h.vuln_class.value,
                "status": h.status.value,
                "information_value": h.information_value,
                "uncertainty": h.uncertainty_score,
                "evidence_count": len(h.supporting_evidence),
            }
            for h in self.rank_hypotheses()[:5]
        ]

        return {
            "total_hypotheses": total,
            "active_hypotheses": active_count,
            "by_status": by_status,
            "by_class": by_class,
            "total_open_proof_gaps": total_open_gaps,
            "average_uncertainty": round(avg_uncertainty, 2),
            "total_actions_recorded": len(self.action_log),
            "top_hypotheses": top_hyps,
        }

