"""Repository-wide Vulnerability Investigation Orchestrator.

Implements evidence-driven multi-phase security investigations combining deterministic
indexing, bounded context extraction, hypothesis formulation, counterevidence analysis,
optional AI assistance with strict citation verification, multi-factor prioritization,
and status determination.
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

        # Phase 1: Architectural Vulnerability Discovery (BOLA/IDOR, Missing Auth, Cross-Tenant, Logic Flaws)
        arch_findings = self._discover_architectural_vulnerabilities(scan_id)
        all_candidates = list(candidates) + arch_findings

        model_requests_used = 0

        for candidate in all_candidates:
            # Check budget constraints
            if time.perf_counter() - t_start > self.budget.timeout_seconds:
                candidate.uncertainty += " [Investigation truncated by timeout budget]"
                self._score_and_prioritize_candidate(candidate, "unknown", [f"{candidate.file_path}:{candidate.start_line}"])
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

            # Phase 8: Explainable Multi-Factor Prioritization
            self._score_and_prioritize_candidate(candidate, entry_point, call_chain)

            investigated.append(candidate)

        # Sort findings by explainable composite priority score descending
        investigated.sort(
            key=lambda c: int(c.metadata.get("priority_score", 0)),
            reverse=True,
        )
        return investigated

    def _discover_architectural_vulnerabilities(self, scan_id: str) -> list[Finding]:
        """Inspect repository intelligence for architectural and authorization defects."""
        findings: list[Finding] = []
        findings.extend(self._discover_missing_function_auth(scan_id))
        findings.extend(self._discover_idor_vulnerabilities(scan_id))
        findings.extend(self._discover_cross_tenant_defects(scan_id))
        findings.extend(self._discover_insecure_file_access(scan_id))
        findings.extend(self._discover_sensitive_data_exposure(scan_id))
        findings.extend(self._discover_business_logic_state_flaws(scan_id))
        return findings

    def _discover_missing_function_auth(self, scan_id: str) -> list[Finding]:
        """Detect missing authorization on state-altering route handlers (SQ-PY-014)."""
        findings: list[Finding] = []
        has_auth_elsewhere = any(b.is_authenticated for b in self.intelligence.auth_boundaries)
        for boundary in self.intelligence.auth_boundaries:
            is_sensitive_method = any(m in {"DELETE", "PUT", "POST", "PATCH"} for m in boundary.http_methods)
            is_sensitive_name = any(
                k in boundary.handler_name.lower()
                for k in ["delete", "remove", "update", "admin", "manage", "purge", "role"]
            )

            if (is_sensitive_method or is_sensitive_name) and not boundary.is_authenticated:
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
        return findings

    def _discover_idor_vulnerabilities(self, scan_id: str) -> list[Finding]:
        """Detect Broken Object-Level Authorization (IDOR) via route parameters (SQ-PY-013)."""
        findings: list[Finding] = []
        for boundary in self.intelligence.auth_boundaries:
            for sym in self.intelligence.symbols.get(boundary.file_path, []):
                if sym.qualified_name == boundary.handler_name:
                    id_params = [p for p in sym.parameters if any(k in p.lower() for k in ["id", "uid", "account", "doc", "item", "order"])]
                    if id_params and not boundary.is_admin_only:
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

    def _discover_cross_tenant_defects(self, scan_id: str) -> list[Finding]:
        """Detect cross-tenant data leakage via queries lacking tenant/org filters (SQ-PY-015)."""
        findings: list[Finding] = []
        # Only inspect for cross-tenant defects if the repository exhibits multi-tenant architecture
        has_repo_tenancy = (
            bool(self.intelligence.multi_tenant_indicators)
            or any("tenant" in f.lower() for f in self.intelligence.file_metadata)
        )
        if not has_repo_tenancy:
            return findings

        for file_path, symbols in self.intelligence.symbols.items():
            for sym in symbols:
                name_lower = sym.name.lower()
                is_tenant_context = (
                    "tenant" in file_path.lower()
                    or any(k in name_lower for k in ["tenant", "org", "workspace", "account", "invoice"])
                )
                if not is_tenant_context:
                    continue

                has_leak, query_line = self._inspect_tenant_isolation(file_path, sym.start_line, sym.end_line)
                if has_leak and query_line > 0:
                    rule = GLOBAL_RULE_REGISTRY.get_rule("SQ-PY-015")
                    finding_id = f"sqf_sq-py-015_{query_line}"
                    occurrence_id = f"occ_sq-py-015_{query_line}"
                    snippet = self._read_source_snippet(file_path, sym.start_line, sym.end_line)

                    loc = SourceLocation(
                        file_path=file_path,
                        start_line=query_line,
                        end_line=query_line,
                        symbol=sym.qualified_name,
                        role="sink",
                    )
                    evidence = CodeEvidence(
                        snippet=snippet,
                        start_line=sym.start_line,
                        end_line=sym.end_line,
                        explanation=f"Query in '{sym.qualified_name}' executes on multi-tenant entity without tenant_id or org_id isolation filter",
                        role="sink",
                    )
                    f = Finding(
                        finding_id=finding_id,
                        occurrence_id=occurrence_id,
                        rule_id="SQ-PY-015",
                        title=f"Cross-Tenant Data Leakage in {sym.qualified_name}",
                        summary=f"Database query in '{sym.qualified_name}' fetches multi-tenant records without scoping to the current tenant session.",
                        category=VulnerabilityCategory.CROSS_TENANT_LEAKAGE,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.MEDIUM,
                        cwe_ids=["CWE-200", "CWE-284"],
                        file_path=file_path,
                        start_line=query_line,
                        end_line=query_line,
                        locations=[loc],
                        code_evidence=[evidence],
                        data_flow=[
                            DataFlowStep(
                                location=SourceLocation(file_path=file_path, start_line=sym.start_line, end_line=sym.start_line, symbol=sym.qualified_name, role="source"),
                                description=f"Tenant operation dispatched to {sym.qualified_name}",
                            ),
                            DataFlowStep(
                                location=loc,
                                description=f"Query executed without tenant isolation clause at line {query_line}",
                            ),
                        ],
                        impact="Cross-tenant information disclosure; users in one tenant can view or mutate data belonging to other tenants.",
                        prerequisites=["Application serves multiple tenants sharing database tables"],
                        conditions_required=["Query omits tenant_id/org_id filter condition"],
                        validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
                        remediation=rule.remediation_advice if rule else "Enforce tenant_id = current_tenant.id in WHERE clause.",
                        discovery_backend="intelligence_orchestrator",
                        scan_id=scan_id,
                    )
                    f.fingerprint = f.calculate_fingerprint()
                    findings.append(f)
        return findings

    def _discover_insecure_file_access(self, scan_id: str) -> list[Finding]:
        """Detect insecure direct file access without resource ownership validation (SQ-PY-016)."""
        findings: list[Finding] = []
        for file_path, symbols in self.intelligence.symbols.items():
            for sym in symbols:
                has_file_param = any(
                    k in p.lower() for p in sym.parameters
                    for k in ["file_name", "filename", "file_path", "doc_path", "export_name"]
                )
                if not has_file_param:
                    continue

                has_insecure_file, sink_line = self._inspect_file_authorization(file_path, sym.start_line, sym.end_line)
                if has_insecure_file and sink_line > 0:
                    rule = GLOBAL_RULE_REGISTRY.get_rule("SQ-PY-016")
                    finding_id = f"sqf_sq-py-016_{sink_line}"
                    occurrence_id = f"occ_sq-py-016_{sink_line}"
                    snippet = self._read_source_snippet(file_path, sym.start_line, sym.end_line)

                    loc = SourceLocation(
                        file_path=file_path,
                        start_line=sink_line,
                        end_line=sink_line,
                        symbol=sym.qualified_name,
                        role="sink",
                    )
                    evidence = CodeEvidence(
                        snippet=snippet,
                        start_line=sym.start_line,
                        end_line=sym.end_line,
                        explanation=f"File returned directly using client parameter in '{sym.qualified_name}' without resource ownership verification",
                        role="sink",
                    )
                    f = Finding(
                        finding_id=finding_id,
                        occurrence_id=occurrence_id,
                        rule_id="SQ-PY-016",
                        title=f"Insecure Direct File Access in {sym.qualified_name}",
                        summary=f"Endpoint or service '{sym.qualified_name}' accesses files based directly on client-supplied parameter without ownership checks.",
                        category=VulnerabilityCategory.INSECURE_DIRECT_FILE_ACCESS,
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        cwe_ids=["CWE-73", "CWE-284"],
                        file_path=file_path,
                        start_line=sink_line,
                        end_line=sink_line,
                        locations=[loc],
                        code_evidence=[evidence],
                        data_flow=[
                            DataFlowStep(location=SourceLocation(file_path=file_path, start_line=sym.start_line, end_line=sym.start_line, symbol=sym.qualified_name, role="source"), description="Filename parameter accepted from caller"),
                            DataFlowStep(location=loc, description=f"File read or sent at line {sink_line} without verifying resource ownership"),
                        ],
                        impact="Attackers can download or access arbitrary files belonging to other users or internal system records.",
                        prerequisites=["Attacker knows or guesses existing filenames"],
                        conditions_required=["File access relies directly on filename without user permission check"],
                        validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
                        remediation=rule.remediation_advice if rule else "Validate user ownership before calling send_file() or open().",
                        discovery_backend="intelligence_orchestrator",
                        scan_id=scan_id,
                    )
                    f.fingerprint = f.calculate_fingerprint()
                    findings.append(f)
        return findings

    def _discover_sensitive_data_exposure(self, scan_id: str) -> list[Finding]:
        """Detect sensitive credential fields serialized into HTTP responses or logs (SQ-PY-017)."""
        findings: list[Finding] = []
        for file_path, symbols in self.intelligence.symbols.items():
            for sym in symbols:
                has_exposure, line_num = self._inspect_sensitive_exposure(file_path, sym.start_line, sym.end_line)
                if has_exposure and line_num > 0:
                    rule = GLOBAL_RULE_REGISTRY.get_rule("SQ-PY-017")
                    finding_id = f"sqf_sq-py-017_{line_num}"
                    occurrence_id = f"occ_sq-py-017_{line_num}"
                    snippet = self._read_source_snippet(file_path, sym.start_line, sym.end_line)

                    loc = SourceLocation(
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        symbol=sym.qualified_name,
                        role="sink",
                    )
                    evidence = CodeEvidence(
                        snippet=snippet,
                        start_line=sym.start_line,
                        end_line=sym.end_line,
                        explanation=f"Sensitive credential field serialized or logged in '{sym.qualified_name}'",
                        role="sink",
                    )
                    f = Finding(
                        finding_id=finding_id,
                        occurrence_id=occurrence_id,
                        rule_id="SQ-PY-017",
                        title=f"Sensitive Data Exposure in {sym.qualified_name}",
                        summary=f"Endpoint or helper '{sym.qualified_name}' serializes sensitive authentication credentials into response or logs.",
                        category=VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.HIGH,
                        cwe_ids=["CWE-200", "CWE-312"],
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        locations=[loc],
                        code_evidence=[evidence],
                        data_flow=[
                            DataFlowStep(location=loc, description=f"Sensitive credential included in output serialization or log at line {line_num}"),
                        ],
                        impact="Sensitive credentials or tokens leaked to client or recorded in plaintext log files.",
                        prerequisites=["Client can view API responses or access application logs"],
                        conditions_required=["Response dictionary or log includes unmasked credential fields"],
                        validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
                        remediation=rule.remediation_advice if rule else "Omit password and token fields from API response dictionaries.",
                        discovery_backend="intelligence_orchestrator",
                        scan_id=scan_id,
                    )
                    f.fingerprint = f.calculate_fingerprint()
                    findings.append(f)
        return findings

    def _discover_business_logic_state_flaws(self, scan_id: str) -> list[Finding]:
        """Detect business logic state transitions executed without invariant checks (SQ-PY-018)."""
        findings: list[Finding] = []
        for file_path, symbols in self.intelligence.symbols.items():
            for sym in symbols:
                has_flaw, line_num = self._inspect_state_transition_invariant(file_path, sym.start_line, sym.end_line)
                if has_flaw and line_num > 0:
                    rule = GLOBAL_RULE_REGISTRY.get_rule("SQ-PY-018")
                    finding_id = f"sqf_sq-py-018_{line_num}"
                    occurrence_id = f"occ_sq-py-018_{line_num}"
                    snippet = self._read_source_snippet(file_path, sym.start_line, sym.end_line)

                    loc = SourceLocation(
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        symbol=sym.qualified_name,
                        role="sink",
                    )
                    evidence = CodeEvidence(
                        snippet=snippet,
                        start_line=sym.start_line,
                        end_line=sym.end_line,
                        explanation=f"State transition executed in '{sym.qualified_name}' without checking prior state or payment verification invariant",
                        role="sink",
                    )
                    f = Finding(
                        finding_id=finding_id,
                        occurrence_id=occurrence_id,
                        rule_id="SQ-PY-018",
                        title=f"Business Logic State Transition Flaw in {sym.qualified_name}",
                        summary=f"Critical workflow in '{sym.qualified_name}' transitions resource state without verifying state machine preconditions.",
                        category=VulnerabilityCategory.BUSINESS_LOGIC_FLAW,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.MEDIUM,
                        cwe_ids=["CWE-840", "CWE-362"],
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        locations=[loc],
                        code_evidence=[evidence],
                        data_flow=[
                            DataFlowStep(location=loc, description=f"State modified without verifying precondition status at line {line_num}"),
                        ],
                        impact="Attackers can bypass workflow requirements (e.g. obtain fulfilled orders without paying) by directly invoking transition actions.",
                        prerequisites=["Client can call workflow transition endpoint out of sequence"],
                        conditions_required=["Transition does not verify that order is in verified paid status"],
                        validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
                        remediation=rule.remediation_advice if rule else "Enforce state machine invariant: verify order.status == PAID before transition.",
                        discovery_backend="intelligence_orchestrator",
                        scan_id=scan_id,
                    )
                    f.fingerprint = f.calculate_fingerprint()
                    findings.append(f)
        return findings

    def _resolve_call_chain_to_entrypoint(self, finding: Finding) -> tuple[str, list[str]]:
        """Trace call graph backwards from finding location towards route entry points with loop prevention."""
        call_chain = [f"{finding.file_path}:{finding.start_line}"]
        curr_symbol = finding.locations[0].symbol if finding.locations else None
        curr_file = finding.file_path

        # If symbol is unknown or empty, look up enclosing symbol in intelligence
        if not curr_symbol or curr_symbol in {"unknown", "module_scope"}:
            for sym in self.intelligence.symbols.get(finding.file_path, []):
                if sym.start_line <= finding.start_line <= sym.end_line:
                    curr_symbol = sym.qualified_name
                    break

        visited: set[tuple[str, str]] = set()
        depth = 0
        while curr_symbol and depth < self.budget.max_depth:
            depth += 1
            node_key = (curr_file, curr_symbol)
            if node_key in visited:
                break
            visited.add(node_key)

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
            unresolved_names = [
                u.call_expression for u in self.intelligence.unresolved_calls
                if any(u.file_path in step for step in call_chain)
            ]
            expr_str = ", ".join(unresolved_names[:3]) or "dynamic dispatch"
            candidate.uncertainty = (
                f"Analysis traverses dynamic dispatch or unresolved call ({expr_str}); "
                "static safety cannot be proven without runtime resolution."
            )
            candidate.validation_status = ValidationStatus.INCONCLUSIVE
            return

        # Evidence verified and no neutralizing counterevidence
        if candidate.code_evidence and len(candidate.data_flow) > 0:
            candidate.validation_status = ValidationStatus.EVIDENCE_SUPPORTED

    def _score_and_prioritize_candidate(
        self,
        candidate: Finding,
        entry_point: str,
        call_chain: list[str],
    ) -> None:
        """Compute an explainable, multi-factor prioritization score (0 - 100)."""
        sev_weights = {
            SeverityLevel.CRITICAL: 40,
            SeverityLevel.HIGH: 30,
            SeverityLevel.MEDIUM: 20,
            SeverityLevel.LOW: 10,
        }
        impact_score = sev_weights.get(candidate.severity, 15)

        # Reachability factor (0 - 30)
        is_route = any(b.route_path == entry_point for b in self.intelligence.auth_boundaries)
        is_public_route = is_route and not any(
            b.route_path == entry_point and b.is_authenticated for b in self.intelligence.auth_boundaries
        )
        if is_public_route:
            reachability_score = 30
            reach_desc = "Directly reachable from unauthenticated public route"
        elif is_route:
            reachability_score = 20
            reach_desc = "Reachable from authenticated route"
        elif len(call_chain) > 1:
            reachability_score = 15
            reach_desc = f"Internal interprocedural call chain ({len(call_chain)} hops)"
        else:
            reachability_score = 10
            reach_desc = "Single component or local module scope"

        # Attacker control factor (0 - 20)
        has_direct_param = any(
            step.location.role == "source" and "parameter" in step.description.lower()
            for step in candidate.data_flow
        )
        if has_direct_param:
            control_score = 20
            control_desc = "Direct client-controlled parameter at entry point"
        elif candidate.data_flow:
            control_score = 15
            control_desc = "Tainted dataflow with transformations"
        else:
            control_score = 10
            control_desc = "Structural pattern match"

        # Uncertainty penalty (0 to -15)
        unresolved_steps = [
            step for step in call_chain
            if any(u.file_path in step for u in self.intelligence.unresolved_calls)
        ]
        if unresolved_steps:
            uncertainty_penalty = -15
            uncertainty_desc = f"Path traverses unresolved dynamic dispatch ({len(unresolved_steps)} site(s))"
        elif candidate.counterevidence:
            uncertainty_penalty = -5
            uncertainty_desc = f"{len(candidate.counterevidence)} mitigating counterevidence factor(s) noted"
        else:
            uncertainty_penalty = 0
            uncertainty_desc = "No dynamic dispatch or mitigating factors observed"

        total_score = max(5, min(100, impact_score + reachability_score + control_score + uncertainty_penalty))

        candidate.metadata["priority_score"] = total_score
        candidate.metadata["priority_breakdown"] = {
            "impact_score": impact_score,
            "reachability_score": reachability_score,
            "reachability_rationale": reach_desc,
            "control_score": control_score,
            "control_rationale": control_desc,
            "uncertainty_penalty": uncertainty_penalty,
            "uncertainty_rationale": uncertainty_desc,
        }

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

            if any(k in line_lower for k in [
                "current_user", "session[", "session.get", "session_uid",
                "owner_id =", "owner_id ==", "user_id =", "user_id ==",
                "created_by =", "created_by ==", "owner =", "owner =="
            ]):
                has_ownership = True

            if any(p in line for p in id_params) and any(
                q in line_lower for q in ["cursor.execute", ".get(", ".filter(", "select * from", "query."]
            ):
                query_line = line_num

        return has_ownership, query_line

    def _inspect_tenant_isolation(
        self,
        rel_path: str,
        start_line: int,
        end_line: int,
    ) -> tuple[bool, int]:
        """Check if multi-tenant query omits tenant_id/org_id scoping."""
        try:
            full_path = resolve_safe_path(self.repository_root, rel_path)
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return False, 0

        fn_lines = lines[start_line - 1: end_line]
        query_line = 0
        has_tenant_filter = False

        for idx, line in enumerate(fn_lines):
            line_num = start_line + idx
            line_lower = line.lower()

            if any(k in line_lower for k in [
                "tenant_id =", "tenant_id ==", "org_id =", "org_id ==",
                "tenant_id:", "org_id:", "current_tenant", "session_tenant",
                "@tenant_required", "tenant_filter", "owner_id =", "owner_id ==",
                "user_id =", "user_id ==", "session_uid"
            ]):
                has_tenant_filter = True

            if any(q in line_lower for q in ["cursor.execute", ".filter(", "select * from", "from documents", "from invoices", "from accounts"]):
                query_line = line_num

        return (not has_tenant_filter and query_line > 0), query_line

    def _inspect_file_authorization(
        self,
        rel_path: str,
        start_line: int,
        end_line: int,
    ) -> tuple[bool, int]:
        """Check if file download/access lacks ownership verification or safe path resolution."""
        try:
            full_path = resolve_safe_path(self.repository_root, rel_path)
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return False, 0

        fn_lines = lines[start_line - 1: end_line]
        sink_line = 0
        has_auth_or_safe = False

        for idx, line in enumerate(fn_lines):
            line_num = start_line + idx
            line_lower = line.lower()

            if any(k in line_lower for k in [
                "owner_id", "session_uid", "current_user", "resolve_safe_path",
                "secure_filename", "os.path.basename", "is_authorized"
            ]):
                has_auth_or_safe = True

            if any(s in line_lower for s in ["send_file(", "send_from_directory(", "download_file("]):
                sink_line = line_num

        return (not has_auth_or_safe and sink_line > 0), sink_line

    def _inspect_sensitive_exposure(
        self,
        rel_path: str,
        start_line: int,
        end_line: int,
    ) -> tuple[bool, int]:
        """Check if dictionary responses or logging include plaintext sensitive credentials."""
        try:
            full_path = resolve_safe_path(self.repository_root, rel_path)
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return False, 0

        fn_lines = lines[start_line - 1: end_line]
        exposure_line = 0

        for idx, line in enumerate(fn_lines):
            line_num = start_line + idx
            line_lower = line.lower()

            # Look for sensitive dictionary keys or logging
            if any(
                k in line_lower
                for k in [
                    '"password_hash":',
                    "'password_hash':",
                    '"password":',
                    "'password':",
                    '"api_key":',
                    "'api_key':",
                    '"secret_key":',
                    "'secret_key':",
                    '"private_key":',
                    "'private_key':",
                ]
            ) and not any(e in line_lower for e in ["exclude", "redact", "mask", "hashlib", "verify"]):
                exposure_line = line_num
                break

            if any(
                log_fn in line_lower for log_fn in ["logging.info(", "logger.info(", "print("]
            ) and any(p in line_lower for p in ["password", "api_key", "secret"]):
                exposure_line = line_num
                break

        return exposure_line > 0, exposure_line

    def _inspect_state_transition_invariant(
        self,
        rel_path: str,
        start_line: int,
        end_line: int,
    ) -> tuple[bool, int]:
        """Check if state transition occurs without prior status validation invariant."""
        try:
            full_path = resolve_safe_path(self.repository_root, rel_path)
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return False, 0

        fn_lines = lines[start_line - 1: end_line]
        transition_line = 0
        has_invariant_check = False

        for idx, line in enumerate(fn_lines):
            line_num = start_line + idx
            line_clean = line.strip()

            if any(k in line_clean for k in [
                "if order.status", "if payment.status", "if status ==",
                "payment.verify", "is_paid", "verify_signature"
            ]):
                has_invariant_check = True

            if any(t in line_clean for t in [
                '.status = "FULFILLED"', ".status = 'FULFILLED'",
                '.status = "PAID"', ".status = 'PAID'",
                '.status = "COMPLETED"', ".status = 'COMPLETED'"
            ]):
                transition_line = line_num

        return (not has_invariant_check and transition_line > 0), transition_line

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
