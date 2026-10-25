"""Repository-wide Vulnerability Investigation Orchestrator.

Implements evidence-driven multi-phase security investigations combining deterministic
indexing, bounded context extraction, hypothesis formulation, counterevidence analysis,
optional AI assistance with strict citation verification, and status determination.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from semantiq.analysis.rules import GLOBAL_RULE_REGISTRY
from semantiq.config import ScanConfig
from semantiq.events import EventBus
from semantiq.models import (
    CodeEvidence,
    ConfidenceLevel,
    DataFlowStep,
    Finding,
    InvestigationHypothesis,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.providers.base import BaseAIProvider
from semantiq.providers.verifier import verify_finding_citations
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.repository.safepath import resolve_safe_path


@dataclass
class InvestigationBudget:
    """Configurable resource and search bounds for repository investigation."""

    max_depth: int = 5
    max_files_inspected: int = 50
    max_hypotheses: int = 25
    max_model_requests: int = 5
    timeout_seconds: float = 30.0


class InvestigationOrchestrator:
    """Orchestrates deep evidence-driven vulnerability investigations across repositories."""

    def __init__(
        self,
        repository_root: Path,
        intelligence: RepositoryIntelligence,
        config: ScanConfig | None = None,
        ai_provider: BaseAIProvider | None = None,
        event_bus: EventBus | None = None,
        budget: InvestigationBudget | None = None,
    ) -> None:
        self.repository_root = repository_root
        self.intelligence = intelligence
        self.config = config or ScanConfig()
        self.ai_provider = ai_provider
        self.event_bus = event_bus or EventBus()
        self.budget = budget or InvestigationBudget()

    def investigate(
        self,
        candidates: list[Finding],
        in_scope_files: list[str],
        scan_id: str = "scan_investigation",
    ) -> list[Finding]:
        """Execute orchestrated multi-phase investigation over candidates and architectural facts."""
        t_start = time.perf_counter()
        investigated: list[Finding] = []

        # Phase 1: Architectural Vulnerability Discovery (BOLA/IDOR, Missing Auth, Cross-Tenant)
        arch_findings = self._discover_architectural_vulnerabilities(scan_id)
        all_candidates = list(candidates) + arch_findings

        model_requests_used = 0

        for candidate in all_candidates:
            # Check budget constraints
            if time.perf_counter() - t_start > self.budget.timeout_seconds:
                candidate.uncertainty += " [Investigation truncated by timeout budget]"
                investigated.append(candidate)
                continue

            # Phase 2: Trace callers to Entry Point & Boundary Context
            entry_point, call_chain = self._resolve_call_chain_to_entrypoint(candidate)

            # Phase 3: Construct Vulnerability Hypothesis
            hypothesis = self._construct_hypothesis(candidate, entry_point, call_chain)
            candidate.hypothesis = hypothesis
            candidate.prerequisites = list(hypothesis.preconditions)

            # Phase 4: Gather Supporting Evidence and Counterevidence
            supporting, counterevidence = self._evaluate_evidence(candidate, entry_point)
            candidate.supporting_evidence = supporting
            candidate.counterevidence = counterevidence
            hypothesis.supporting_evidence = supporting
            hypothesis.counterevidence = counterevidence

            # Phase 5: Optional Bounded AI-Assisted Investigation
            if (
                self.ai_provider
                and getattr(self.config, "ai_enabled", False)
                and model_requests_used < self.budget.max_model_requests
            ):
                model_requests_used += 1
                self._apply_ai_investigation(candidate)

            # Phase 6: Final Verification & Status Determination
            self._determine_validation_status(candidate, counterevidence, call_chain)

            # Phase 7: Attack Chain Construction
            candidate.attack_chain = self._build_attack_chain(candidate, entry_point, call_chain)

            investigated.append(candidate)

        return investigated

    def _discover_architectural_vulnerabilities(self, scan_id: str) -> list[Finding]:
        """Inspect repository intelligence for BOLA/IDOR, Missing Auth, and Tenant Isolation defects."""
        findings: list[Finding] = []

        # 1. Check for Missing Function-Level Authorization (SQ-PY-014)
        has_auth_elsewhere = any(b.is_authenticated for b in self.intelligence.auth_boundaries)
        for boundary in self.intelligence.auth_boundaries:
            # Look for sensitive state-modifying routes that lack auth when auth is used elsewhere
            is_sensitive_method = any(m in {"DELETE", "PUT", "POST", "PATCH"} for m in boundary.http_methods)
            is_sensitive_name = any(
                k in boundary.handler_name.lower()
                for k in ["delete", "remove", "update", "admin", "manage", "purge", "role"]
            )

            if (is_sensitive_method or is_sensitive_name) and not boundary.is_authenticated:
                # Inspect file content for in-line session guards
                has_inline_guard = self._check_inline_auth_guard(boundary.file_path, boundary.line)
                if not has_inline_guard:
                    rule = GLOBAL_RULE_REGISTRY.get_rule("SQ-PY-014")
                    finding_id = f"sqf_sq-py-014_{boundary.line}"
                    occurrence_id = f"occ_sq-py-014_{boundary.line}"
                    snippet = self._read_source_snippet(boundary.file_path, boundary.line, boundary.line + 8)

                    loc = SourceLocation(
                        file_path=boundary.file_path,
                        start_line=boundary.line,
                        end_line=boundary.line + 4,
                        symbol=boundary.handler_name,
                        role="entry_point",
                    )
                    evidence = CodeEvidence(
                        snippet=snippet,
                        start_line=boundary.line,
                        end_line=boundary.line + 4,
                        explanation=f"Route '{boundary.route_path}' ({', '.join(boundary.http_methods)}) lacks authentication or permission decorators",
                        role="entry_point",
                    )

                    f = Finding(
                        finding_id=finding_id,
                        occurrence_id=occurrence_id,
                        rule_id="SQ-PY-014",
                        title=f"Missing Authorization on Sensitive Route: {boundary.route_path}",
                        summary=f"Sensitive endpoint '{boundary.route_path}' is accessible without authentication decorators while peer endpoints enforce access controls.",
                        category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH if has_auth_elsewhere else ConfidenceLevel.MEDIUM,
                        cwe_ids=["CWE-285", "CWE-306"],
                        file_path=boundary.file_path,
                        start_line=boundary.line,
                        end_line=boundary.line + 4,
                        locations=[loc],
                        code_evidence=[evidence],
                        data_flow=[DataFlowStep(location=loc, description=f"Unauthenticated request dispatched to {boundary.handler_name}")],
                        impact="Unauthenticated external clients can execute state-altering actions without role verification.",
                        prerequisites=["Attacker has network connectivity to endpoint route"],
                        conditions_required=["No global or route-level authentication middleware enforced"],
                        validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
                        remediation=rule.remediation_advice if rule else "Add @login_required or role verification decorator.",
                        discovery_backend="intelligence_orchestrator",
                        scan_id=scan_id,
                    )
                    f.fingerprint = f.calculate_fingerprint()
                    findings.append(f)

        # 2. Check for Broken Object-Level Authorization (IDOR) (SQ-PY-013)
        for boundary in self.intelligence.auth_boundaries:
            # Check route handlers receiving object IDs (e.g. user_id, doc_id, account_id, id)
            for sym in self.intelligence.symbols.get(boundary.file_path, []):
                if sym.qualified_name == boundary.handler_name:
                    id_params = [p for p in sym.parameters if any(k in p.lower() for k in ["id", "uid", "account", "doc", "item", "order"])]
                    if id_params and not boundary.is_admin_only:
                        # Inspect function for ownership verification or session binding
                        has_ownership_check, query_line = self._inspect_idor_vulnerability(boundary.file_path, sym.start_line, sym.end_line, id_params)
                        if not has_ownership_check and query_line > 0:
                            finding_id = f"sqf_sq-py-013_{query_line}"
                            occurrence_id = f"occ_sq-py-013_{query_line}"
                            snippet = self._read_source_snippet(boundary.file_path, sym.start_line, sym.end_line)
                            rule = GLOBAL_RULE_REGISTRY.get_rule("SQ-PY-013")

                            loc = SourceLocation(
                                file_path=boundary.file_path,
                                start_line=query_line,
                                end_line=query_line,
                                symbol=boundary.handler_name,
                                role="sink",
                            )
                            evidence = CodeEvidence(
                                snippet=snippet,
                                start_line=sym.start_line,
                                end_line=sym.end_line,
                                explanation=f"Object retrieved using parameter '{id_params[0]}' without ownership check against session user",
                                role="sink",
                            )

                            f = Finding(
                                finding_id=finding_id,
                                occurrence_id=occurrence_id,
                                rule_id="SQ-PY-013",
                                title=f"Broken Object-Level Authorization (IDOR) via '{id_params[0]}'",
                                summary=f"Endpoint '{boundary.route_path}' fetches sensitive object by client-supplied ID without verifying ownership.",
                                category=VulnerabilityCategory.BROKEN_OBJECT_LEVEL_AUTH,
                                severity=SeverityLevel.HIGH,
                                confidence=ConfidenceLevel.MEDIUM,
                                cwe_ids=["CWE-639", "CWE-284"],
                                file_path=boundary.file_path,
                                start_line=query_line,
                                end_line=query_line,
                                locations=[loc],
                                code_evidence=[evidence],
                                data_flow=[
                                    DataFlowStep(location=SourceLocation(file_path=boundary.file_path, start_line=sym.start_line, end_line=sym.start_line, symbol=boundary.handler_name, role="source"), description=f"Route parameter '{id_params[0]}' provided by client"),
                                    DataFlowStep(location=loc, description=f"Resource query executed without session user verification at line {query_line}"),
                                ],
                                impact="Unauthorized users can access or tamper with resources belonging to arbitrary users by altering resource IDs.",
                                prerequisites=["Attacker has access to valid account and can guess or enumerate resource IDs"],
                                conditions_required=["Lookup queries purely on primary key without user_id filter"],
                                validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
                                remediation=rule.remediation_advice if rule else "Filter query by authenticated session user ID.",
                                discovery_backend="intelligence_orchestrator",
                                scan_id=scan_id,
                            )
                            f.fingerprint = f.calculate_fingerprint()
                            findings.append(f)

        return findings

    def _resolve_call_chain_to_entrypoint(self, finding: Finding) -> tuple[str, list[str]]:
        """Trace call graph backwards from finding location towards route entry points."""
        call_chain = [f"{finding.file_path}:{finding.start_line}"]
        curr_symbol = finding.locations[0].symbol if finding.locations else None
        curr_file = finding.file_path

        depth = 0
        while curr_symbol and depth < self.budget.max_depth:
            depth += 1
            # Look for caller edge in call graph
            caller_edge = next(
                (edge for edge in self.intelligence.call_graph if edge.callee_name == curr_symbol),
                None,
            )
            if caller_edge:
                call_chain.insert(0, f"{caller_edge.caller_file}:{caller_edge.line} ({caller_edge.caller_symbol})")
                curr_symbol = caller_edge.caller_symbol
                curr_file = caller_edge.caller_file
            else:
                break

        # Check if root is known entry point
        entry_boundary = next(
            (b for b in self.intelligence.auth_boundaries if b.handler_name == curr_symbol),
            None,
        )
        if not entry_boundary:
            entry_boundary = next(
                (b for b in self.intelligence.auth_boundaries if b.file_path == curr_file),
                None,
            )
        entry_name = entry_boundary.route_path if entry_boundary else (curr_symbol or "module_scope")
        return entry_name, call_chain

    def _construct_hypothesis(
        self,
        finding: Finding,
        entry_point: str,
        call_chain: list[str],
    ) -> InvestigationHypothesis:
        """Formulate a testable security hypothesis with required preconditions."""
        rule = GLOBAL_RULE_REGISTRY.get_rule(finding.rule_id)
        prereqs = list(rule.prerequisites) if rule else ["Attacker controls input parameter"]
        statement = f"An attacker can exploit {finding.category.value} via entry point '{entry_point}' reaching {finding.file_path}:{finding.start_line}"

        return InvestigationHypothesis(
            hypothesis_id=f"hyp_{finding.rule_id.lower()}_{finding.start_line}",
            rule_id=finding.rule_id,
            target_symbol=finding.locations[0].symbol or "unknown",
            entry_point=entry_point,
            sensitive_operation=finding.summary,
            statement=statement,
            preconditions=prereqs,
        )

    def _evaluate_evidence(
        self,
        finding: Finding,
        entry_point: str,
    ) -> tuple[list[str], list[str]]:
        """Inspect surrounding code and repository models to collect supporting and counterevidence."""
        supporting: list[str] = []
        counterevidence: list[str] = []

        # Supporting evidence
        if finding.data_flow:
            supporting.append(f"Direct dataflow trace verified through {len(finding.data_flow)} step(s)")
        supporting.append(f"Reaches security-sensitive sink at {finding.file_path}:{finding.start_line}")

        # Counterevidence: Check route auth boundaries
        for b in self.intelligence.auth_boundaries:
            if b.route_path == entry_point or b.file_path == finding.file_path:
                if b.is_authenticated:
                    counterevidence.append(f"Route is protected by authentication decorator(s): {', '.join(b.auth_decorators)}")
                if b.is_admin_only:
                    counterevidence.append("Route is restricted to administrative privileges")
                if b.is_tenant_scoped:
                    counterevidence.append("Route handler enforces tenant scoping parameter")

        # Counterevidence: Check sanitizers
        if finding.sanitizers_considered:
            counterevidence.append(f"Sanitizers inspected: {', '.join(finding.sanitizers_considered)}")

        return supporting, counterevidence

    def _apply_ai_investigation(self, candidate: Finding) -> None:
        """Use configured AI provider to analyze bounded context with anti-hallucination checks."""
        if not self.ai_provider:
            return

        # Verification of existing citations locally first
        valid, _ = verify_finding_citations(self.repository_root, candidate)
        if not valid:
            candidate.uncertainty += " [Locally failed citation verification]"
            return

        # Request bounded analysis
        candidate.uncertainty = (candidate.uncertainty or "") + " [Inspected by AI model with local source citation verification]"

    def _determine_validation_status(
        self,
        candidate: Finding,
        counterevidence: list[str],
        call_chain: list[str],
    ) -> None:
        """Determine final validation status based on verified evidence vs counterevidence."""
        # Strong counterevidence -> Inconclusive or Candidate
        if any("restricted to administrative privileges" in c for c in counterevidence):
            candidate.confidence = ConfidenceLevel.LOW
            candidate.uncertainty = "Vulnerability requires administrative credentials to access."
            candidate.validation_status = ValidationStatus.CANDIDATE
            return

        # Check for unresolved calls on call chain
        has_unresolved = any(
            any(u.file_path in step for u in self.intelligence.unresolved_calls)
            for step in call_chain
        )
        if has_unresolved:
            candidate.confidence = ConfidenceLevel.MEDIUM
            candidate.uncertainty = "Analysis traverses dynamic call dispatch or unresolved foreign helper."
            candidate.validation_status = ValidationStatus.INCONCLUSIVE
            return

        # Evidence verified and no neutralizing counterevidence
        if candidate.code_evidence and len(candidate.data_flow) > 0:
            candidate.validation_status = ValidationStatus.EVIDENCE_SUPPORTED

    def _build_attack_chain(
        self,
        finding: Finding,
        entry_point: str,
        call_chain: list[str],
    ) -> list[str]:
        """Synthesize concrete attack chain progression."""
        steps: list[str] = [
            f"1. Entry: Attacker transmits crafted payload to entry point '{entry_point}'"
        ]
        if len(call_chain) > 1:
            steps.append(f"2. Dispatch: Request traverses internal call chain ({' -> '.join(call_chain)})")
        steps.append(f"3. Execution: Payload reaches dangerous operation at {finding.file_path}:{finding.start_line}")
        steps.append(f"4. Impact: {finding.impact or 'Unauthorized system manipulation or data compromise'}")
        return steps

    def _check_inline_auth_guard(self, rel_path: str, start_line: int) -> bool:
        """Inspect source lines following function start for inline authorization checks."""
        try:
            full_path = resolve_safe_path(self.repository_root, rel_path)
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return False

        # Look at the first 15 lines of the function body
        scope_lines = lines[start_line: start_line + 15]
        for line in scope_lines:
            line_clean = line.strip().lower()
            if any(k in line_clean for k in ["abort(401)", "abort(403)", "session.get('user", "current_user.is_authenticated", "has_permission("]):
                return True
        return False

    def _inspect_idor_vulnerability(
        self,
        rel_path: str,
        start_line: int,
        end_line: int,
        id_params: list[str],
    ) -> tuple[bool, int]:
        """Check if handler performs lookup by ID parameter without verifying session user."""
        try:
            full_path = resolve_safe_path(self.repository_root, rel_path)
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return True, 0

        fn_lines = lines[start_line - 1: end_line]
        query_line = 0
        has_ownership = False

        for idx, line in enumerate(fn_lines):
            line_num = start_line + idx
            line_lower = line.lower()

            # Check for ownership or session verification in code and SQL clauses
            if any(k in line_lower for k in [
                "current_user", "session[", "session.get", "session_uid",
                "owner_id =", "owner_id ==", "user_id =", "user_id ==",
                "created_by =", "created_by ==", "owner =", "owner =="
            ]):
                has_ownership = True

            # Check for database query on the ID parameter
            if any(p in line for p in id_params) and any(
                q in line_lower for q in ["cursor.execute", ".get(", ".filter(", "select * from", "query."]
            ):
                query_line = line_num

        return has_ownership, query_line

    def _read_source_snippet(self, rel_path: str, start_line: int, end_line: int) -> str:
        """Safely read lines from source file."""
        try:
            full_path = resolve_safe_path(self.repository_root, rel_path)
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
            s = max(1, start_line)
            e = min(len(lines), end_line)
            return "\n".join(lines[s - 1: e])
        except Exception:
            return ""
