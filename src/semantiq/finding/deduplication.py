"""Evidence-preserving deduplication pipeline with root-cause equivalence assessment.

Staged deduplication pipeline:
1. Deterministic canonical ordering and structural candidate grouping.
2. Symmetric pairwise equivalence decision matrix across all pairs within structural buckets.
3. Constrained complete-linkage clustering preventing false transitivity.
4. Evidence-preserving merge retaining all 7 code evidence roles, reconciling proof gaps,
   grounding severity and confidence, and maintaining worker provenance.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from semantiq.finding.identity import (
    SemanticFindingIdentity,
)
from semantiq.models import (
    CodeEvidence,
    ConfidenceLevel,
    Finding,
    FindingLifecycleState,
    ProofGap,
    ProofGapStatus,
    SeverityLevel,
    ValidationStatus,
)

logger = logging.getLogger(__name__)


class EquivalenceOutcome(str, Enum):
    """Pairwise equivalence assessment outcome."""

    SAME = "SAME"
    DISTINCT = "DISTINCT"
    UNCERTAIN = "UNCERTAIN"


class EquivalenceDecision(BaseModel):
    """Detailed audit record of pairwise finding equivalence assessment."""

    model_config = ConfigDict(frozen=True)

    outcome: EquivalenceOutcome
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    matched_invariants: list[str] = Field(default_factory=list)
    differing_dimensions: list[str] = Field(default_factory=list)
    primary_finding_id: str
    secondary_finding_id: str


class MergeAuditRecord(BaseModel):
    """Audit record capturing an evidence-preserving merge operation."""

    model_config = ConfigDict(frozen=True)

    merge_id: str
    primary_finding_id: str
    merged_finding_ids: list[str]
    decision_outcome: EquivalenceOutcome
    equivalence_confidence: float
    merge_rationale: str
    evidence_ids_merged: list[str]
    contributing_workers: list[str]


class DeduplicationResult(BaseModel):
    """Overall outcome of the deduplication pipeline."""

    model_config = ConfigDict(frozen=True)

    consolidated_findings: list[Finding]
    audit_records: list[EquivalenceDecision]
    merge_records: list[MergeAuditRecord]
    total_raw_findings: int
    merged_count: int
    distinct_count: int
    uncertain_count: int
    secondary_duplicate_findings: list[Finding] = Field(default_factory=list)


class SemanticDeduplicator:
    """Staged, evidence-preserving finding deduplication engine."""

    def __init__(self, semantic_threshold: float = 0.75) -> None:
        self.semantic_threshold = semantic_threshold

    def assess_pairwise_equivalence(
        self,
        finding_a: Finding,
        identity_a: SemanticFindingIdentity,
        finding_b: Finding,
        identity_b: SemanticFindingIdentity,
    ) -> EquivalenceDecision:
        """Evaluate whether two findings represent the same underlying security defect.

        Guaranteed symmetric: assess(a, b) and assess(b, a) produce identical outcomes.
        """
        matched: list[str] = []
        differing: list[str] = []

        # 1. Compare Security Invariant & Root Cause Family
        if identity_a.security_invariant == identity_b.security_invariant:
            matched.append(f"invariant:{identity_a.security_invariant.value}")
        else:
            differing.append(f"invariant({identity_a.security_invariant.value} vs {identity_b.security_invariant.value})")

        if identity_a.root_cause_family == identity_b.root_cause_family:
            matched.append(f"root_cause:{identity_a.root_cause_family.value}")
        else:
            differing.append(f"root_cause({identity_a.root_cause_family.value} vs {identity_b.root_cause_family.value})")

        # Invariant or root-cause mismatch strictly precludes equivalence
        if identity_a.security_invariant != identity_b.security_invariant or identity_a.root_cause_family != identity_b.root_cause_family:
            return EquivalenceDecision(
                outcome=EquivalenceOutcome.DISTINCT,
                confidence=0.95,
                rationale=(
                    f"Orthogonal security defects: Invariant '{identity_a.security_invariant.value}' vs '{identity_b.security_invariant.value}', "
                    f"Root cause '{identity_a.root_cause_family.value}' vs '{identity_b.root_cause_family.value}'."
                ),
                matched_invariants=matched,
                differing_dimensions=differing,
                primary_finding_id=finding_a.finding_id,
                secondary_finding_id=finding_b.finding_id,
            )

        # 2. Compare Target Sink (Must be concrete and non-empty to count as a match)
        sink_a = identity_a.target_sink.strip().lower()
        sink_b = identity_b.target_sink.strip().lower()
        has_concrete_sink_match = bool(sink_a and sink_b and sink_a == sink_b and sink_a != "unknown_sink")
        if has_concrete_sink_match:
            matched.append(f"sink:{sink_a}")
        elif sink_a and sink_b and sink_a != sink_b:
            differing.append(f"sink({sink_a} vs {sink_b})")

        # 3. Compare Subsystem / Module
        sub_a = identity_a.subsystem_or_module.strip().lower()
        sub_b = identity_b.subsystem_or_module.strip().lower()
        if sub_a and sub_a == sub_b:
            matched.append(f"subsystem:{sub_a}")
        elif sub_a and sub_b and sub_a != sub_b:
            differing.append(f"subsystem({sub_a} vs {sub_b})")

        # 4. Compare Entry Points
        ep_a = identity_a.entry_point.strip().lower()
        ep_b = identity_b.entry_point.strip().lower()
        has_entrypoint_match = bool(ep_a and ep_b and ep_a == ep_b)
        if has_entrypoint_match:
            matched.append(f"entrypoint:{ep_a}")
        elif ep_a and ep_b and ep_a != ep_b:
            differing.append(f"entrypoint({ep_a} vs {ep_b})")

        # 5. Check File and Line Locality
        file_a = finding_a.file_path.replace("\\", "/").strip().lower()
        file_b = finding_b.file_path.replace("\\", "/").strip().lower()
        same_file = file_a == file_b
        line_distance = abs(finding_a.start_line - finding_b.start_line)

        # ---------------------------------------------------------------------
        # Evaluation Cases:
        # ---------------------------------------------------------------------

        # Case A: Same File Locality
        if same_file:
            # Case A1: Exact identical line range and same root cause -> SAME
            if finding_a.start_line == finding_b.start_line and finding_a.end_line == finding_b.end_line:
                return EquivalenceDecision(
                    outcome=EquivalenceOutcome.SAME,
                    confidence=0.99,
                    rationale=(
                        f"Exact duplicate report at {finding_a.file_path}:{finding_a.start_line}-{finding_a.end_line} "
                        f"violating invariant '{identity_a.security_invariant.value}'."
                    ),
                    matched_invariants=matched,
                    differing_dimensions=differing,
                    primary_finding_id=finding_a.finding_id,
                    secondary_finding_id=finding_b.finding_id,
                )

            # Case A2: In same file but differing entry points or symbols -> DISTINCT
            if ep_a and ep_b and ep_a != ep_b and not has_concrete_sink_match:
                return EquivalenceDecision(
                    outcome=EquivalenceOutcome.DISTINCT,
                    confidence=0.90,
                    rationale=(
                        f"Colocated in {finding_a.file_path} but represent distinct endpoints/functions: "
                        f"'{identity_a.entry_point}' vs '{identity_b.entry_point}'."
                    ),
                    matched_invariants=matched,
                    differing_dimensions=differing,
                    primary_finding_id=finding_a.finding_id,
                    secondary_finding_id=finding_b.finding_id,
                )

            # Case A3: Differing sinks in same file -> DISTINCT
            if sink_a and sink_b and sink_a != sink_b:
                return EquivalenceDecision(
                    outcome=EquivalenceOutcome.DISTINCT,
                    confidence=0.90,
                    rationale=(
                        f"Colocated in {finding_a.file_path} but reaching different sensitive sinks: "
                        f"'{sink_a}' vs '{sink_b}'."
                    ),
                    matched_invariants=matched,
                    differing_dimensions=differing,
                    primary_finding_id=finding_a.finding_id,
                    secondary_finding_id=finding_b.finding_id,
                )

            # Case A4: Shared entry point or shared concrete sink within the same file -> SAME
            if has_entrypoint_match or has_concrete_sink_match:
                return EquivalenceDecision(
                    outcome=EquivalenceOutcome.SAME,
                    confidence=0.95,
                    rationale=(
                        f"Colocated within {line_distance} lines in {finding_a.file_path} sharing "
                        f"identical invariant ({identity_a.security_invariant.value}) and verified "
                        f"{'entrypoint (' + ep_a + ')' if has_entrypoint_match else 'sink (' + sink_a + ')'}."
                    ),
                    matched_invariants=matched,
                    differing_dimensions=differing,
                    primary_finding_id=finding_a.finding_id,
                    secondary_finding_id=finding_b.finding_id,
                )

            # Case A5: Overlapping or immediately adjacent lines within a tightly scoped block (<= 5 lines)
            if line_distance <= 5:
                return EquivalenceDecision(
                    outcome=EquivalenceOutcome.SAME,
                    confidence=0.90,
                    rationale=(
                        f"Tightly colocated within {line_distance} lines in {finding_a.file_path} "
                        f"sharing root cause '{identity_a.root_cause_family.value}'."
                    ),
                    matched_invariants=matched,
                    differing_dimensions=differing,
                    primary_finding_id=finding_a.finding_id,
                    secondary_finding_id=finding_b.finding_id,
                )

            # Do NOT merge distinct endpoints merely because they are in the same file or within 25 lines
            return EquivalenceDecision(
                outcome=EquivalenceOutcome.DISTINCT,
                confidence=0.85,
                rationale=(
                    f"Colocated in {finding_a.file_path} ({line_distance} lines apart) without "
                    "shared entrypoint, symbol, or verified sink."
                ),
                matched_invariants=matched,
                differing_dimensions=differing,
                primary_finding_id=finding_a.finding_id,
                secondary_finding_id=finding_b.finding_id,
            )

        # Case B: Cross-File / Cross-Endpoint Comparison
        # Cross-file equivalence strictly requires matching verified concrete sinks and attacker capability
        if (
            has_concrete_sink_match
            and identity_a.required_capability == identity_b.required_capability
        ):
            return EquivalenceDecision(
                outcome=EquivalenceOutcome.SAME,
                confidence=0.90,
                rationale=(
                    f"Cross-endpoint architectural equivalence: Both endpoints share root cause '{identity_a.root_cause_family.value}', "
                    f"violating invariant '{identity_a.security_invariant.value}' reaching common verified sink '{identity_a.target_sink}'."
                ),
                matched_invariants=matched,
                differing_dimensions=differing,
                primary_finding_id=finding_a.finding_id,
                secondary_finding_id=finding_b.finding_id,
            )

        # In cross-file comparisons without a concrete matching sink, findings are DISTINCT
        if not has_concrete_sink_match:
            return EquivalenceDecision(
                outcome=EquivalenceOutcome.DISTINCT,
                confidence=0.85,
                rationale=(
                    f"Distinct vulnerability occurrences in separate files ({finding_a.file_path} vs {finding_b.file_path}) "
                    "lacking verified identical sensitive sink evidence."
                ),
                matched_invariants=matched,
                differing_dimensions=differing,
                primary_finding_id=finding_a.finding_id,
                secondary_finding_id=finding_b.finding_id,
            )

        # Default fallback
        return EquivalenceDecision(
            outcome=EquivalenceOutcome.UNCERTAIN,
            confidence=0.50,
            rationale="Partial overlap in security dimensions without definitive root cause equivalence.",
            matched_invariants=matched,
            differing_dimensions=differing,
            primary_finding_id=finding_a.finding_id,
            secondary_finding_id=finding_b.finding_id,
        )

    def merge_findings(
        self,
        primary: Finding,
        secondary: Finding,
        decision: EquivalenceDecision,
    ) -> tuple[Finding, MergeAuditRecord]:
        """Execute an evidence-preserving merge, retaining all evidence hops, reconciling proof gaps,
        grounding severity and confidence, and preserving worker provenance.
        """
        # 1. Union of code evidence preserving IDs and all 7 semantic roles
        merged_evidence: list[CodeEvidence] = list(primary.code_evidence)
        seen_ev_ids = {e.evidence_id for e in merged_evidence if e.evidence_id}

        for ev in secondary.code_evidence:
            if ev.evidence_id and ev.evidence_id not in seen_ev_ids:
                merged_evidence.append(ev)
                seen_ev_ids.add(ev.evidence_id)
            elif not ev.evidence_id and ev not in merged_evidence:
                merged_evidence.append(ev)

        # 2. Reconcile proof gaps preserving scope, resolution evidence, and proven resolutions
        reconciled_gaps_map: dict[str, ProofGap] = {}
        for pg in list(primary.proof_gaps) + list(secondary.proof_gaps):
            key = pg.gap_id or f"{pg.target_symbol}:{pg.description}".lower().strip()
            if key not in reconciled_gaps_map:
                reconciled_gaps_map[key] = pg.model_copy()
            else:
                existing = reconciled_gaps_map[key]
                combined_ev = sorted(list(set(existing.supporting_evidence + pg.supporting_evidence)))
                # Status reconciliation
                if existing.status == ProofGapStatus.RESOLVED and pg.status == ProofGapStatus.OPEN:
                    reconciled_gaps_map[key] = existing.model_copy(update={"supporting_evidence": combined_ev})
                elif existing.status == ProofGapStatus.OPEN and pg.status == ProofGapStatus.RESOLVED:
                    if pg.supporting_evidence:
                        # Legitimate verified resolution supported by evidence
                        reconciled_gaps_map[key] = pg.model_copy(update={"supporting_evidence": combined_ev})
                    else:
                        # Resolution claim lacks supporting evidence: preserve OPEN status with note
                        reconciled_gaps_map[key] = existing.model_copy(
                            update={
                                "supporting_evidence": combined_ev + ["Unverified resolution claim from secondary without evidence"],
                                "status": ProofGapStatus.OPEN,
                            }
                        )
                else:
                    reconciled_gaps_map[key] = existing.model_copy(update={"supporting_evidence": combined_ev})

        merged_gaps = list(reconciled_gaps_map.values())

        # 3. Preserve contributing workers and finding identities
        merged_metadata = dict(primary.metadata or {})
        workers: list[str] = []
        for f in (primary, secondary):
            if f.metadata:
                if "worker_id" in f.metadata:
                    workers.append(str(f.metadata["worker_id"]))
                if "contributing_worker" in f.metadata:
                    workers.append(str(f.metadata["contributing_worker"]))
                if "contributing_workers" in f.metadata and isinstance(f.metadata["contributing_workers"], list):
                    workers.extend(f.metadata["contributing_workers"])
        existing_workers = sorted(list(set(workers)))
        merged_metadata["contributing_workers"] = existing_workers

        merged_finding_ids = list(merged_metadata.get("merged_finding_ids", [primary.finding_id]))
        if secondary.finding_id not in merged_finding_ids:
            merged_finding_ids.append(secondary.finding_id)
        merged_metadata["merged_finding_ids"] = merged_finding_ids
        merged_metadata["duplicate_finding_ids"] = [fid for fid in merged_finding_ids if fid != primary.finding_id]

        # 4. Retain contradictory / counterevidence notes
        merged_counter = list(primary.counterevidence or [])
        for c in (secondary.counterevidence or []):
            if c not in merged_counter:
                merged_counter.append(c)

        # 5. Preserve independent exploit paths & locations
        merged_locations = list(primary.locations or [])
        for loc in (secondary.locations or []):
            if loc not in merged_locations:
                merged_locations.append(loc)

        # 6. Synthesize comprehensive description if helpful
        new_summary = primary.summary
        if len(secondary.summary) > len(primary.summary) and primary.summary in secondary.summary:
            new_summary = secondary.summary
        elif secondary.summary and secondary.summary not in primary.summary:
            new_summary = f"{primary.summary}\n[Additional Path Context]: {secondary.summary}"

        # ---------------------------------------------------------------------
        # 7. Grounded Severity and Confidence Determination
        # ---------------------------------------------------------------------
        has_verified_sink = any(
            ev.role == "sink" or (hasattr(ev.role, "value") and ev.role.value == "sink")
            for ev in merged_evidence
        )
        p_verified = (primary.validation_status == ValidationStatus.VALIDATED) or bool(primary.code_evidence)
        s_verified = (secondary.validation_status == ValidationStatus.VALIDATED) or bool(secondary.code_evidence)

        open_critical_gaps = [
            g for g in merged_gaps
            if g.status == ProofGapStatus.OPEN and any(kw in g.description.lower() for kw in ("reach", "guard", "impact", "exploit"))
        ]

        sev_ranks = {
            SeverityLevel.INFORMATIONAL: 1,
            SeverityLevel.LOW: 2,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.HIGH: 4,
            SeverityLevel.CRITICAL: 5,
        }
        p_sev_rank = sev_ranks.get(primary.severity, 1)
        s_sev_rank = sev_ranks.get(secondary.severity, 1)

        if p_sev_rank == s_sev_rank:
            if p_sev_rank >= 4 and not has_verified_sink:
                new_severity = SeverityLevel.MEDIUM
                merged_metadata["hypothesized_severity"] = primary.severity.value
                merged_metadata["severity_justification"] = (
                    f"Canonical severity bounded to medium pending verified sink evidence. "
                    f"Claim of {primary.severity.value} retained as hypothesis."
                )
            else:
                new_severity = primary.severity
        elif s_sev_rank > p_sev_rank:
            # Secondary claims higher severity. An unverified worker cannot unilaterally elevate to CRITICAL or HIGH.
            if s_sev_rank >= 4 and not (s_verified and has_verified_sink):
                new_severity = primary.severity
                merged_metadata["hypothesized_severity"] = secondary.severity.value
                merged_metadata["unverified_escalation_worker"] = secondary.metadata.get("worker_id", "unknown")
                merged_metadata["severity_justification"] = (
                    f"Preserved grounded severity {primary.severity.value}. Escalation to {secondary.severity.value} "
                    f"by {secondary.finding_id} remains an unverified hypothesis pending sink impact verification."
                )
            else:
                new_severity = secondary.severity
        else:
            # Primary claims higher severity (p_sev_rank > s_sev_rank).
            # An unverified claim cannot retain CRITICAL or HIGH without verified sink evidence.
            if p_sev_rank >= 4 and not (p_verified and has_verified_sink):
                new_severity = secondary.severity
                merged_metadata["hypothesized_severity"] = primary.severity.value
                merged_metadata["unverified_escalation_worker"] = primary.metadata.get("worker_id", "unknown")
                merged_metadata["severity_justification"] = (
                    f"Preserved grounded severity {secondary.severity.value}. Escalation to {primary.severity.value} "
                    f"by {primary.finding_id} remains an unverified hypothesis pending sink impact verification."
                )
            else:
                new_severity = primary.severity

        # Grounded Confidence: Reflect evidence quality, corroboration, and unresolved proof gaps
        if open_critical_gaps:
            new_confidence = ConfidenceLevel.MEDIUM if (primary.confidence == ConfidenceLevel.HIGH or secondary.confidence == ConfidenceLevel.HIGH) else ConfidenceLevel.LOW
            merged_metadata["confidence_rationale"] = (
                f"Confidence bounded to {new_confidence.value} due to {len(open_critical_gaps)} unresolved proof obligations."
            )
        else:
            if len(existing_workers) > 1 and (p_verified or s_verified):
                new_confidence = ConfidenceLevel.HIGH
            else:
                conf_ranks = {ConfidenceLevel.LOW: 1, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.HIGH: 3}
                p_c_rank = conf_ranks.get(primary.confidence, 1)
                s_c_rank = conf_ranks.get(secondary.confidence, 1)
                new_confidence = secondary.confidence if s_c_rank > p_c_rank else primary.confidence

        merged_finding = primary.model_copy(
            update={
                "code_evidence": merged_evidence,
                "proof_gaps": merged_gaps,
                "metadata": merged_metadata,
                "counterevidence": merged_counter,
                "locations": merged_locations,
                "summary": new_summary,
                "confidence": new_confidence,
                "severity": new_severity,
            }
        )

        merge_record = MergeAuditRecord(
            merge_id=f"merge_{primary.finding_id[:8]}_{secondary.finding_id[:8]}",
            primary_finding_id=primary.finding_id,
            merged_finding_ids=merged_finding_ids,
            decision_outcome=decision.outcome,
            equivalence_confidence=decision.confidence,
            merge_rationale=decision.rationale,
            evidence_ids_merged=list(seen_ev_ids),
            contributing_workers=existing_workers,
        )

        return merged_finding, merge_record

    def deduplicate(
        self,
        findings: list[Finding],
        graph: Any | None = None,
    ) -> DeduplicationResult:
        """Run deterministic constrained clustering deduplication across all candidate findings."""
        if not findings:
            return DeduplicationResult(
                consolidated_findings=[],
                audit_records=[],
                merge_records=[],
                total_raw_findings=0,
                merged_count=0,
                distinct_count=0,
                uncertain_count=0,
                secondary_duplicate_findings=[],
            )

        # Stage 1: Stable canonical candidate sorting
        def canonical_key(f: Finding) -> tuple[str, str, int, int, str]:
            return (
                f.finding_id,
                f.file_path.replace("\\", "/").lower(),
                f.start_line,
                f.end_line,
                f.rule_id,
            )

        sorted_candidates = sorted(findings, key=canonical_key)

        # Stage 2: Compute Semantic Finding Identities
        identities: dict[str, SemanticFindingIdentity] = {
            f.finding_id: SemanticFindingIdentity.from_finding(f, graph=graph)
            for f in sorted_candidates
        }

        # Stage 3: Group candidates by structural hash (invariant + root cause + capability)
        groups: dict[str, list[Finding]] = {}
        for f in sorted_candidates:
            struct_key = identities[f.finding_id].structural_hash
            groups.setdefault(struct_key, []).append(f)

        consolidated: list[Finding] = []
        secondary_duplicates: list[Finding] = []
        audit_decisions: list[EquivalenceDecision] = []
        merge_records: list[MergeAuditRecord] = []

        total_merged = 0
        total_distinct = 0
        total_uncertain = 0

        # Stage 4: Constrained clustering within each structural bucket
        for _struct_key, bucket in groups.items():
            n = len(bucket)
            if n == 1:
                consolidated.append(bucket[0])
                total_distinct += 1
                continue

            # Compute pairwise decision matrix across all pairs in the bucket
            pairwise_matrix: dict[tuple[int, int], EquivalenceDecision] = {}
            for i in range(n):
                for j in range(i + 1, n):
                    decision = self.assess_pairwise_equivalence(
                        bucket[i],
                        identities[bucket[i].finding_id],
                        bucket[j],
                        identities[bucket[j].finding_id],
                    )
                    pairwise_matrix[(i, j)] = decision
                    pairwise_matrix[(j, i)] = decision
                    audit_decisions.append(decision)

            # Constrained complete-linkage cluster formation
            clusters: list[list[int]] = []

            for cand_idx in range(n):
                eligible_clusters: list[tuple[int, float]] = []

                for c_idx, cluster in enumerate(clusters):
                    # Check complete-linkage compatibility: cand_idx must be SAME with EVERY member in cluster
                    is_compatible = True
                    conf_sum = 0.0

                    for member_idx in cluster:
                        dec = pairwise_matrix[(min(cand_idx, member_idx), max(cand_idx, member_idx))]
                        if dec.outcome != EquivalenceOutcome.SAME:
                            is_compatible = False
                            break
                        conf_sum += dec.confidence

                    if is_compatible:
                        avg_conf = conf_sum / len(cluster)
                        eligible_clusters.append((c_idx, avg_conf))

                if not eligible_clusters:
                    # Starts a new cluster
                    clusters.append([cand_idx])
                elif len(eligible_clusters) == 1:
                    clusters[eligible_clusters[0][0]].append(cand_idx)
                else:
                    # Deterministic tie-breaking: highest average confidence, then lowest cluster index
                    eligible_clusters.sort(key=lambda x: (-x[1], x[0]))
                    clusters[eligible_clusters[0][0]].append(cand_idx)

            # Cluster Consolidation
            for cluster in clusters:
                if len(cluster) == 1:
                    cand = bucket[cluster[0]]
                    consolidated.append(cand)
                    # Check if candidate had any UNCERTAIN relationships
                    has_uncertain = any(
                        pairwise_matrix.get((min(cluster[0], j), max(cluster[0], j))) is not None
                        and pairwise_matrix[(min(cluster[0], j), max(cluster[0], j))].outcome == EquivalenceOutcome.UNCERTAIN
                        for j in range(n) if j != cluster[0]
                    )
                    if has_uncertain:
                        total_uncertain += 1
                    else:
                        total_distinct += 1
                else:
                    # Multi-member cluster: primary is the first candidate in canonical sort order
                    primary = bucket[cluster[0]]
                    for sec_idx in cluster[1:]:
                        secondary = bucket[sec_idx]
                        dec = pairwise_matrix[(min(cluster[0], sec_idx), max(cluster[0], sec_idx))]
                        primary, m_rec = self.merge_findings(primary, secondary, dec)
                        merge_records.append(m_rec)
                        total_merged += 1

                        # Mark secondary finding as DUPLICATE and preserve its record
                        sec_dup = secondary.model_copy(
                            update={
                                "lifecycle_state": FindingLifecycleState.DUPLICATE,
                                "metadata": {
                                    **(secondary.metadata or {}),
                                    "primary_finding_id": primary.finding_id,
                                    "duplicate_of": primary.finding_id,
                                    "merge_id": m_rec.merge_id,
                                },
                            }
                        )
                        secondary_duplicates.append(sec_dup)

                    consolidated.append(primary)

        # Sort consolidated findings by canonical key for deterministic output
        consolidated.sort(key=canonical_key)

        return DeduplicationResult(
            consolidated_findings=consolidated,
            audit_records=audit_decisions,
            merge_records=merge_records,
            total_raw_findings=len(findings),
            merged_count=total_merged,
            distinct_count=total_distinct,
            uncertain_count=total_uncertain,
            secondary_duplicate_findings=secondary_duplicates,
        )
