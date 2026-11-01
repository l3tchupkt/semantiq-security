"""Evidence reducer consolidating multi-perspective worker outputs, reconciling contradictions, and preserving proof gaps."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from semantiq.analysis.path_adversarial import PathAdversarialVerifier
from semantiq.discovery.workers.models import WorkerOutput, WorkerRole
from semantiq.finding.deduplication import EquivalenceOutcome, SemanticDeduplicator
from semantiq.models import (
    Finding,
    FindingLifecycleState,
    ValidationStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class ReducerDecision:
    """Decision record tracking how a candidate finding was handled during reduction."""

    decision_id: str
    finding_id: str
    outcome: str  # ACCEPTED, MERGED, CONTRADICTED, REJECTED, DUPLICATE, UNCERTAIN
    reason: str
    contributing_workers: list[str] = field(default_factory=list)
    decided_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "finding_id": self.finding_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "contributing_workers": self.contributing_workers,
            "decided_at": self.decided_at,
        }


@dataclass
class ReducerResult:
    """Consolidated findings and audit trails produced by the InvestigationReducer."""

    consolidated_findings: list[Finding]
    audit_records: list[ReducerDecision]
    total_raw_findings: int
    accepted_count: int
    merged_count: int
    contradicted_count: int
    rejected_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_raw_findings": self.total_raw_findings,
            "accepted_count": self.accepted_count,
            "merged_count": self.merged_count,
            "contradicted_count": self.contradicted_count,
            "rejected_count": self.rejected_count,
            "consolidated_findings_count": len(self.consolidated_findings),
            "audit_records": [a.to_dict() for a in self.audit_records],
        }


class InvestigationReducer:
    """Reduces and reconciles independent candidate findings and hypotheses across workers."""

    def __init__(self, repository_root: Path | str | None = None) -> None:
        self.repository_root = Path(repository_root).resolve() if repository_root else None
        self.deduplicator = SemanticDeduplicator()
        self.path_verifier = PathAdversarialVerifier(repository_root=self.repository_root)

    def reduce(self, worker_outputs: list[WorkerOutput], graph: Any | None = None) -> ReducerResult:
        """Consolidate findings across all workers, compare root causes, resolve contradictions, and preserve evidence."""
        raw_findings: list[tuple[Finding, str, WorkerRole]] = []

        # 1. Harvest raw findings from all workers
        for out in worker_outputs:
            w_id = out.worker_id
            w_role = out.worker_role
            for f in out.candidate_findings:
                # Store worker_id in finding metadata for provenance tracking
                if not f.metadata:
                    f.metadata = {}
                f.metadata.setdefault("worker_id", w_id)
                f.metadata.setdefault("worker_role", w_role.value)
                raw_findings.append((f, w_id, w_role))

        total_raw = len(raw_findings)
        if not raw_findings:
            return ReducerResult(
                consolidated_findings=[],
                audit_records=[],
                total_raw_findings=0,
                accepted_count=0,
                merged_count=0,
                contradicted_count=0,
                rejected_count=0,
            )

        decisions: list[ReducerDecision] = []
        contradicted_cnt = 0
        rejected_cnt = 0

        # 2. Path-Specific Adversarial Verification & Contradiction Resolution
        surviving_findings: list[Finding] = []
        for f, w_id, _w_role in raw_findings:
            eval_res = self.path_verifier.evaluate_finding_defenses(f, graph=graph)
            if eval_res.contradicts_finding:
                # Finding legitimately contradicted by an active, mandatory neutralizing guard on its path
                f.lifecycle_state = FindingLifecycleState.REJECTED
                f.validation_status = ValidationStatus.REJECTED
                f.counterevidence.append(eval_res.rationale)

                decisions.append(
                    ReducerDecision(
                        decision_id=f"dec_contra_{f.finding_id[:8]}",
                        finding_id=f.finding_id,
                        outcome="CONTRADICTED",
                        reason=eval_res.rationale,
                        contributing_workers=[w_id],
                    )
                )
                contradicted_cnt += 1
                rejected_cnt += 1
                surviving_findings.append(f)
            else:
                if eval_res.bypass_paths:
                    # Document any partial guards or bypass conditions as counterevidence notes without rejecting
                    f.counterevidence.append(eval_res.rationale)
                surviving_findings.append(f)

        # Separate candidates to be deduplicated (active candidates) vs already rejected
        active_candidates = [
            f for f in surviving_findings if f.lifecycle_state != FindingLifecycleState.REJECTED
        ]
        already_rejected = [
            f for f in surviving_findings if f.lifecycle_state == FindingLifecycleState.REJECTED
        ]

        # 3. Evidence-Preserving Deduplication via Semantic Finding Identity
        dedup_res = self.deduplicator.deduplicate(active_candidates, graph=graph)

        # Convert deduplication audit records to ReducerDecisions
        for decision in dedup_res.audit_records:
            if decision.outcome == EquivalenceOutcome.SAME:
                decisions.append(
                    ReducerDecision(
                        decision_id=f"dec_merge_{decision.primary_finding_id[:8]}_{decision.secondary_finding_id[:8]}",
                        finding_id=decision.primary_finding_id,
                        outcome="MERGED",
                        reason=decision.rationale,
                        contributing_workers=[
                            decision.primary_finding_id,
                            decision.secondary_finding_id,
                        ],
                    )
                )
            elif decision.outcome == EquivalenceOutcome.UNCERTAIN:
                decisions.append(
                    ReducerDecision(
                        decision_id=f"dec_uncert_{decision.primary_finding_id[:8]}_{decision.secondary_finding_id[:8]}",
                        finding_id=decision.secondary_finding_id,
                        outcome="UNCERTAIN",
                        reason=decision.rationale,
                        contributing_workers=[decision.secondary_finding_id],
                    )
                )

        consolidated = list(dedup_res.consolidated_findings)
        # Append secondary duplicate findings so their identities and evidence are preserved in SQLite and SARIF
        for sec in dedup_res.secondary_duplicate_findings:
            decisions.append(
                ReducerDecision(
                    decision_id=f"dec_dup_{sec.finding_id[:8]}",
                    finding_id=sec.finding_id,
                    outcome="DUPLICATE",
                    reason=f"Merged into canonical primary finding {sec.metadata.get('primary_finding_id', '')}",
                    contributing_workers=sec.metadata.get(
                        "contributing_workers", [sec.metadata.get("worker_id", "")]
                    ),
                )
            )
        consolidated.extend(dedup_res.secondary_duplicate_findings)
        # Append already-rejected findings so they remain in the audit record and SARIF
        consolidated.extend(already_rejected)

        accepted_cnt = len(dedup_res.consolidated_findings)
        merged_cnt = dedup_res.merged_count

        for f in dedup_res.consolidated_findings:
            if not any(
                d.finding_id == f.finding_id and d.outcome in ("MERGED", "CONTRADICTED")
                for d in decisions
            ):
                decisions.append(
                    ReducerDecision(
                        decision_id=f"dec_accept_{f.finding_id[:8]}",
                        finding_id=f.finding_id,
                        outcome="ACCEPTED",
                        reason="Verified independent finding with grounded code evidence",
                        contributing_workers=f.metadata.get(
                            "contributing_workers", [f.metadata.get("worker_id", "")]
                        ),
                    )
                )

        logger.info(
            "InvestigationReducer completed: raw=%d, consolidated=%d (accepted=%d, merged=%d, contradicted=%d, rejected=%d)",
            total_raw,
            len(consolidated),
            accepted_cnt,
            merged_cnt,
            contradicted_cnt,
            rejected_cnt,
        )

        return ReducerResult(
            consolidated_findings=consolidated,
            audit_records=decisions,
            total_raw_findings=total_raw,
            accepted_count=accepted_cnt,
            merged_count=merged_cnt,
            contradicted_count=contradicted_cnt,
            rejected_count=rejected_cnt,
        )

    def reduce_skill_outputs(
        self,
        skill_outputs: list[Any],
        graph: Any | None = None,
    ) -> ReducerResult:
        """Consolidate findings across skill execution outputs while preserving skill provenance and proof gaps."""
        worker_outputs: list[WorkerOutput] = []

        for so in skill_outputs:
            findings = getattr(so, "findings", []) or []
            rejected = getattr(so, "rejected_findings", []) or []
            combined = list(findings) + list(rejected)
            if not combined:
                continue

            skill_id = getattr(so, "skill_id", "unknown_skill")
            telemetry = getattr(so, "telemetry", None)

            for f in combined:
                if not f.metadata:
                    f.metadata = {}
                f.metadata.setdefault("skill_id", skill_id)
                f.metadata.setdefault("worker_id", f"skill_{skill_id}")
                if telemetry:
                    f.metadata.setdefault("skill_telemetry", telemetry)

            worker_outputs.append(
                WorkerOutput(
                    worker_id=f"skill_worker_{skill_id.split('.')[-1]}",
                    worker_role=WorkerRole.DISCOVERY,
                    packet_id=f"pkt_{skill_id}",
                    candidate_findings=combined,
                )
            )

        return self.reduce(worker_outputs, graph=graph)
