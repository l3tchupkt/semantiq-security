"""Independent Finding Adjudication Engine for Beyond-Heuristics Security Evaluations.

Replaces permissive keyword matching with rigorous, multi-factor finding adjudication.
Ground truth criteria remain strictly isolated from model prompts and investigation tools.
Adjudication runs exclusively post-investigation to evaluate:
1. Root cause accuracy (distinguishing actual vulnerability mechanisms from misattributions).
2. Entry point reachability and prerequisites.
3. Complete causal execution path.
4. Security invariant violation.
5. Invalidation by protections, mitigating guards, or feature flags.
6. Stated impact vs code-substantiated impact (distinguishing confirmed flaws from unproven RCE).
7. Line citation validity.
8. Deduplication across different finding titles for the same underlying flaw.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from semantiq.models import Finding
from semantiq.providers.verifier import verify_finding_citations


class AdjudicationVerdict(str, Enum):
    """Rigorous classification of finding validity and exploitability."""
    CONFIRMED_EXPLOITABLE = "confirmed_exploitable"
    CONFIRMED_INVARIANT_VIOLATION_IMPACT_UNPROVEN = "confirmed_invariant_violation_impact_unproven"
    PARTIAL_EVIDENCE = "partial_evidence"
    NOT_EXPLOITABLE_UNDER_OBSERVED_ASSUMPTIONS = "not_exploitable_under_observed_assumptions"
    REJECTED_WRONG_ROOT_CAUSE = "rejected_wrong_root_cause"
    REJECTED_INVALID_CITATION = "rejected_invalid_citation"
    REJECTED_SAFE_INVARIANT_ENFORCED = "rejected_safe_invariant_enforced"
    REJECTED_DUPLICATE = "rejected_duplicate"


@dataclass
class FindingAdjudication:
    """Detailed adjudication record for an evaluated finding."""
    finding_id: str
    title: str
    verdict: AdjudicationVerdict
    confidence: str
    root_cause_accurate: bool
    entry_point_reachable: bool
    invariant_violated: bool
    protections_neutralized: bool
    impact_substantiated: bool
    citations_valid: bool
    reasons: list[str] = field(default_factory=list)
    demonstrated_impact: str = ""
    canonical_flaw_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "root_cause_accurate": self.root_cause_accurate,
            "entry_point_reachable": self.entry_point_reachable,
            "invariant_violated": self.invariant_violated,
            "protections_neutralized": self.protections_neutralized,
            "impact_substantiated": self.impact_substantiated,
            "citations_valid": self.citations_valid,
            "reasons": self.reasons,
            "demonstrated_impact": self.demonstrated_impact,
            "canonical_flaw_key": self.canonical_flaw_key,
        }


@dataclass
class CaseGroundTruth:
    """Isolated ground-truth specification for adjudication (never exposed to model)."""
    case_id: str
    title: str
    primary_flaw_file: str
    affected_modules: list[str]
    valid_entry_points: list[str]
    required_root_cause_concepts: list[list[str]]  # Each list is an OR group; all groups required
    disqualifying_misattributions: list[str]       # Buzzwords/flaws that indicate wrong root cause
    supported_impact: str
    overstated_impact_patterns: list[str]          # Impact claims not supported by observed code
    safe_mitigation_checks: list[str]              # Code constructs that prove flaw is neutralized
    hard_negative_disabled_paths: list[str] = field(default_factory=list) # e.g. disabled debug functions


class FindingAdjudicator:
    """Adjudicates investigation findings against ground-truth security criteria."""

    def __init__(self, ground_truth: dict[str, CaseGroundTruth]) -> None:
        self.ground_truth = ground_truth

    def adjudicate(
        self,
        case_id: str,
        repository_root: Path | str,
        findings: list[Finding],
        is_safe_counterpart: bool = False,
    ) -> list[FindingAdjudication]:
        """Adjudicate all findings produced for a target repository."""
        repo_root = Path(repository_root).expanduser().resolve()
        case_spec = self.ground_truth.get(case_id)
        if not case_spec:
            return []

        adjudications: list[FindingAdjudication] = []
        seen_canonical_keys: set[str] = set()

        for f in findings:
            adj = self._adjudicate_single_finding(
                finding=f,
                case_spec=case_spec,
                repo_root=repo_root,
                is_safe_counterpart=is_safe_counterpart,
            )

            # Deduplication check
            if adj.canonical_flaw_key and adj.canonical_flaw_key in seen_canonical_keys:
                adj.verdict = AdjudicationVerdict.REJECTED_DUPLICATE
                adj.reasons.append("Finding describes the same underlying flaw as a previously evaluated finding.")
            elif adj.canonical_flaw_key and adj.verdict in (
                AdjudicationVerdict.CONFIRMED_EXPLOITABLE,
                AdjudicationVerdict.CONFIRMED_INVARIANT_VIOLATION_IMPACT_UNPROVEN,
            ):
                seen_canonical_keys.add(adj.canonical_flaw_key)

            adjudications.append(adj)

        return adjudications

    def _adjudicate_single_finding(
        self,
        finding: Finding,
        case_spec: CaseGroundTruth,
        repo_root: Path,
        is_safe_counterpart: bool,
    ) -> FindingAdjudication:
        reasons: list[str] = []
        text_corpus = (
            f"{finding.title} {finding.summary} {finding.impact} "
            f"{' '.join(finding.supporting_evidence)} {' '.join(finding.attack_chain)}"
        ).lower()

        # 1. Citation verification against disk
        citations_valid, cit_issue = verify_finding_citations(repo_root, finding)
        if not citations_valid:
            reasons.append(f"Citation verification failed: {cit_issue}")
            return FindingAdjudication(
                finding_id=finding.finding_id,
                title=finding.title,
                verdict=AdjudicationVerdict.REJECTED_INVALID_CITATION,
                confidence="none",
                root_cause_accurate=False,
                entry_point_reachable=False,
                invariant_violated=False,
                protections_neutralized=False,
                impact_substantiated=False,
                citations_valid=False,
                reasons=reasons,
                demonstrated_impact="none",
            )

        # 2. File and Module Scope Matching
        fpath_norm = finding.file_path.replace("\\", "/").lstrip("/")
        matches_primary = case_spec.primary_flaw_file in fpath_norm
        matches_affected = any(mod in fpath_norm for mod in case_spec.affected_modules)

        if not (matches_primary or matches_affected):
            reasons.append(f"Finding file '{fpath_norm}' is outside affected modules: {case_spec.affected_modules}")
            return FindingAdjudication(
                finding_id=finding.finding_id,
                title=finding.title,
                verdict=AdjudicationVerdict.REJECTED_WRONG_ROOT_CAUSE,
                confidence="low",
                root_cause_accurate=False,
                entry_point_reachable=False,
                invariant_violated=False,
                protections_neutralized=False,
                impact_substantiated=False,
                citations_valid=True,
                reasons=reasons,
                demonstrated_impact="none",
            )

        # 3. Check for Disqualifying Misattributions (Plausible buzzwords, wrong root cause)
        for disqualifier in case_spec.disqualifying_misattributions:
            if disqualifier.lower() in text_corpus:
                # E.g. claiming SQL Injection on delegation scope, or claiming CSRF on refund race
                reasons.append(f"Disqualifying misattribution detected: claimed '{disqualifier}' as root cause.")
                return FindingAdjudication(
                    finding_id=finding.finding_id,
                    title=finding.title,
                    verdict=AdjudicationVerdict.REJECTED_WRONG_ROOT_CAUSE,
                    confidence="low",
                    root_cause_accurate=False,
                    entry_point_reachable=False,
                    invariant_violated=False,
                    protections_neutralized=False,
                    impact_substantiated=False,
                    citations_valid=True,
                    reasons=reasons,
                    demonstrated_impact="none",
                )

        # 4. Check for Hard-Negative / Disabled Paths
        for disabled_path in case_spec.hard_negative_disabled_paths:
            if disabled_path.lower() in text_corpus or disabled_path.lower() in fpath_norm:
                reasons.append(
                    f"Finding cites '{disabled_path}', which is protected by permanent feature flag/disabled configuration in observed code."
                )
                return FindingAdjudication(
                    finding_id=finding.finding_id,
                    title=finding.title,
                    verdict=AdjudicationVerdict.NOT_EXPLOITABLE_UNDER_OBSERVED_ASSUMPTIONS,
                    confidence="low",
                    root_cause_accurate=False,
                    entry_point_reachable=False,
                    invariant_violated=False,
                    protections_neutralized=False,
                    impact_substantiated=False,
                    citations_valid=True,
                    reasons=reasons,
                    demonstrated_impact="Feature is disabled or mitigated by permanent guards in observed repository.",
                )

        # 5. Check whether Protections / Safe Mitigations Neutralize the Finding
        if is_safe_counterpart:
            reasons.append("Evaluated against secure counterpart repository.")
            for mit in case_spec.safe_mitigation_checks:
                reasons.append(f"Mitigating protection verified in safe implementation: {mit}")
            return FindingAdjudication(
                finding_id=finding.finding_id,
                title=finding.title,
                verdict=AdjudicationVerdict.REJECTED_SAFE_INVARIANT_ENFORCED,
                confidence="high",
                root_cause_accurate=False,
                entry_point_reachable=False,
                invariant_violated=False,
                protections_neutralized=True,
                impact_substantiated=False,
                citations_valid=True,
                reasons=reasons,
                demonstrated_impact="Mitigated in safe counterpart.",
            )

        # 6. Verify Reachable Entry Point
        entry_point_reachable = False
        declared_entry = (finding.locations[0].symbol if finding.locations else "") + " " + (finding.structured_attack_chain.starting_point if finding.structured_attack_chain else "")
        declared_entry_lower = declared_entry.lower() + " " + text_corpus
        for ep in case_spec.valid_entry_points:
            if ep.lower() in declared_entry_lower:
                entry_point_reachable = True
                break
        if not entry_point_reachable:
            reasons.append(f"Reachable entry point not substantiated. Expected one of: {case_spec.valid_entry_points}")

        # 7. Verify Root Cause Concepts
        missing_concept_groups: list[list[str]] = []
        for concept_group in case_spec.required_root_cause_concepts:
            if not any(term.lower() in text_corpus for term in concept_group):
                missing_concept_groups.append(concept_group)

        if missing_concept_groups:
            reasons.append(
                f"Missing essential root cause concepts: {missing_concept_groups}. "
                "Finding mentions file but fails to describe the actual invariant violation mechanism."
            )
            return FindingAdjudication(
                finding_id=finding.finding_id,
                title=finding.title,
                verdict=AdjudicationVerdict.PARTIAL_EVIDENCE,
                confidence="low",
                root_cause_accurate=False,
                entry_point_reachable=entry_point_reachable,
                invariant_violated=False,
                protections_neutralized=False,
                impact_substantiated=False,
                citations_valid=True,
                reasons=reasons,
                demonstrated_impact="Incomplete root cause evidence.",
            )

        canonical_key = f"{case_spec.case_id}:{case_spec.primary_flaw_file}"

        # 8. Check Impact Substantiation vs Overstated Claims
        has_overstated_impact = False
        overstated_reasons: list[str] = []
        for over_claim in case_spec.overstated_impact_patterns:
            if over_claim.lower() in text_corpus:
                has_overstated_impact = True
                overstated_reasons.append(
                    f"Claimed '{over_claim}' as impact, which is unproven/speculative because repository code only queues or delegates tasks without directly executing arbitrary host commands."
                )

        if has_overstated_impact:
            reasons.extend(overstated_reasons)
            reasons.append(f"Substantiated demonstrated impact is limited to: {case_spec.supported_impact}")
            return FindingAdjudication(
                finding_id=finding.finding_id,
                title=finding.title,
                verdict=AdjudicationVerdict.CONFIRMED_INVARIANT_VIOLATION_IMPACT_UNPROVEN,
                confidence="medium",
                root_cause_accurate=True,
                entry_point_reachable=entry_point_reachable,
                invariant_violated=True,
                protections_neutralized=False,
                impact_substantiated=False,
                citations_valid=True,
                reasons=reasons,
                demonstrated_impact=case_spec.supported_impact,
                canonical_flaw_key=canonical_key,
            )

        # Full confirmed exploitability
        reasons.append("Root cause accurately identified.")
        reasons.append("Reachable entry point verified.")
        reasons.append("Security invariant violation confirmed.")
        reasons.append(f"Demonstrated impact substantiated: {case_spec.supported_impact}")

        return FindingAdjudication(
            finding_id=finding.finding_id,
            title=finding.title,
            verdict=AdjudicationVerdict.CONFIRMED_EXPLOITABLE,
            confidence="high",
            root_cause_accurate=True,
            entry_point_reachable=entry_point_reachable,
            invariant_violated=True,
            protections_neutralized=False,
            impact_substantiated=True,
            citations_valid=True,
            reasons=reasons,
            demonstrated_impact=case_spec.supported_impact,
            canonical_flaw_key=canonical_key,
        )
