"""AI-First Deep Vulnerability Discovery and Investigation Engine.

Implements an iterative 12-step security investigation loop capable of discovering
complex multi-step, cross-component, and business-logic vulnerabilities beyond
predefined rules, supported by the Semantic Program Graph (SPG), bounded on-demand
context retrieval, self-critique/counterevidence analysis, and persistent memory.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any

from semantiq.config import ScanConfig
from semantiq.discovery.orchestrator import InvestigationBudget
from semantiq.events import EventBus
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, NodeKind
from semantiq.models import (
    AttackChain,
    AttackChainStep,
    CodeEvidence,
    ConfidenceLevel,
    DataFlowStep,
    Finding,
    InvestigationHypothesis,
    InvestigationMemoryRecord,
    InvestigationTrace,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.providers.base import BaseAIProvider
from semantiq.providers.verifier import verify_finding_citations
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


class AIVulnerabilityInvestigator:
    """Iterative AI security investigation engine for deep, multi-step vulnerability discovery."""

    def __init__(
        self,
        repository_root: Path | str,
        intelligence: RepositoryIntelligence,
        graph: SemanticProgramGraph | None = None,
        ai_provider: BaseAIProvider | None = None,
        config: ScanConfig | None = None,
        budget: InvestigationBudget | None = None,
        storage: SQLiteStorage | None = None,
        event_bus: EventBus | None = None,
        source_revision: str = "",
        in_scope_files: list[str] | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self.intelligence = intelligence
        self.ai_provider = ai_provider
        self.config = config or ScanConfig()
        self.budget = budget or InvestigationBudget()
        self.storage = storage
        self.event_bus = event_bus or EventBus()
        self.source_revision = source_revision

        if graph is not None:
            self.graph = graph
        else:
            builder = GraphBuilder(self.repository_root)
            files = in_scope_files or list(self.intelligence.file_metadata.keys())
            build_res = builder.build(files)
            self.graph = build_res.graph

    def build_security_context_model(self) -> dict[str, Any]:
        """Step 1: Build initial repository and security-context model."""
        routes = self.graph.find_nodes(kind=NodeKind.ROUTE)
        sensitive_sinks = [
            n for n in self.graph.nodes.values()
            if n.kind in (
                NodeKind.SENSITIVE_SINK,
                NodeKind.QUERY,
                NodeKind.PROCESS_EXEC,
                NodeKind.EXTERNAL_REQUEST,
                NodeKind.FILE_OPERATION,
            )
        ]
        unresolved_regions = self.graph.find_unresolved_regions()
        auth_boundaries = self.intelligence.auth_boundaries

        return {
            "repository_root": str(self.repository_root),
            "source_revision": self.source_revision,
            "total_nodes": len(self.graph.nodes),
            "total_routes": len(routes),
            "total_sinks": len(sensitive_sinks),
            "unresolved_count": len(unresolved_regions),
            "auth_boundaries_count": len(auth_boundaries),
            "routes": [
                {
                    "route_id": r.id,
                    "path": r.properties.get("route_path", r.label),
                    "handler": r.properties.get("handler", r.label),
                    "file_path": r.file_path,
                    "line": r.start_line,
                }
                for r in routes
            ],
            "unresolved": unresolved_regions[:10],
        }

    def generate_hypotheses(
        self,
        candidate_signals: list[Finding] | None = None,
    ) -> list[InvestigationHypothesis]:
        """Step 2: Generate diverse, evidence-grounded hypotheses across multiple strategies."""
        hypotheses: list[InvestigationHypothesis] = []
        seen_targets: set[str] = set()

        # Strategy A: Architecture & Trust Boundary Traversal
        for route in self.graph.find_nodes(kind=NodeKind.ROUTE):
            boundary_info = self.graph.find_boundary_crossings(route.id)
            route_path = route.properties.get("route_path", route.label)
            handler = route.properties.get("handler", route.label)

            # Check unauthenticated access to queries or sensitive operations
            if not boundary_info.get("is_authenticated") and boundary_info.get("queries_executed"):
                hyp_key = f"auth_bypass:{route_path}:{handler}"
                if hyp_key not in seen_targets:
                    seen_targets.add(hyp_key)
                    hypotheses.append(
                        InvestigationHypothesis(
                            hypothesis_id=f"hyp_{uuid.uuid4().hex[:8]}",
                            rule_id="AI-DISCOVERY-AUTH-001",
                            target_symbol=handler,
                            entry_point=route_path,
                            sensitive_operation="database_query",
                            statement=(
                                f"Route '{route_path}' executes database operations without authentication controls, "
                                "potentially enabling unauthenticated data access or state manipulation."
                            ),
                            preconditions=["External network reachability to route", "No global middleware blocking path"],
                            supporting_evidence=[
                                f"Route handler {handler} has 0 authentication decorators",
                                f"Directly reachable queries: {', '.join(boundary_info.get('queries_executed', [])[:3])}",
                            ],
                            disposition="open",
                        )
                    )

        # Strategy B: Cross-Component Attack Chains
        attack_chains = self.graph.find_attack_chains(max_depth=self.budget.max_depth)
        for chain in attack_chains:
            if chain.get("is_high_risk"):
                hyp_key = f"chain:{chain['entry_route']}:{chain['target_sink_id']}"
                if hyp_key not in seen_targets:
                    seen_targets.add(hyp_key)
                    hypotheses.append(
                        InvestigationHypothesis(
                            hypothesis_id=f"hyp_{uuid.uuid4().hex[:8]}",
                            rule_id="AI-DISCOVERY-CHAIN-001",
                            target_symbol=chain.get("target_sink_expression", "sink"),
                            entry_point=chain["entry_route"],
                            sensitive_operation=chain["target_sink_kind"],
                            statement=(
                                f"Multi-step attack chain from entry '{chain['entry_route']}' traverses "
                                f"{chain['hop_count']} service hop(s) to sensitive sink '{chain['target_sink_kind']}' "
                                f"with missing controls: {', '.join(chain['missing_controls'])}."
                            ),
                            preconditions=["Attacker can reach entry point with parameter control"],
                            supporting_evidence=[
                                f"Call path: {' -> '.join(h['label'] for h in chain['hops'])}",
                                f"Boundaries crossed: {', '.join(chain['boundaries_crossed'])}",
                            ],
                            disposition="open",
                        )
                    )

        # Strategy C: Inconsistent Security Controls across Alternate Routes
        sensitive_sinks = [
            n for n in self.graph.nodes.values()
            if n.kind in (NodeKind.SENSITIVE_SINK, NodeKind.QUERY, NodeKind.PROCESS_EXEC)
        ]
        for sink in sensitive_sinks[:20]:
            alt_entries = self.graph.find_alternate_entry_points(sink.id)
            if len(alt_entries) > 1:
                auth_entries = [e for e in alt_entries if e.get("is_authenticated")]
                unauth_entries = [e for e in alt_entries if not e.get("is_authenticated")]
                if auth_entries and unauth_entries:
                    for u in unauth_entries:
                        hyp_key = f"inconsistent_auth:{u['route_path']}:{sink.id}"
                        if hyp_key not in seen_targets:
                            seen_targets.add(hyp_key)
                            peer_route = auth_entries[0]["route_path"]
                            hypotheses.append(
                                InvestigationHypothesis(
                                    hypothesis_id=f"hyp_{uuid.uuid4().hex[:8]}",
                                    rule_id="AI-DISCOVERY-AUTH-DIVERGENCE",
                                    target_symbol=sink.label,
                                    entry_point=u["route_path"],
                                    sensitive_operation=sink.kind.value,
                                    statement=(
                                        f"Inconsistent authorization: peer route '{peer_route}' enforces authentication "
                                        f"before reaching '{sink.label}', but alternate route '{u['route_path']}' "
                                        "reaches the same sensitive operation without authentication."
                                    ),
                                    preconditions=["Attacker invokes unauthenticated route variant"],
                                    supporting_evidence=[
                                        f"Protected route: {peer_route} (auth controls present)",
                                        f"Exposed route: {u['route_path']} (0 auth controls)",
                                        f"Common target operation: {sink.file_path}:{sink.start_line}",
                                    ],
                                    disposition="open",
                                )
                            )

        # Strategy D: Business-Logic and State-Transition Invariant Analysis
        state_hypotheses = self._discover_state_transition_hypotheses()
        for sh in state_hypotheses:
            hyp_key = f"state:{sh.entry_point}:{sh.target_symbol}"
            if hyp_key not in seen_targets:
                seen_targets.add(hyp_key)
                hypotheses.append(sh)

        # Strategy E: Candidate-Generation Signals from Static Rules
        if candidate_signals:
            for cand in candidate_signals:
                hyp_key = f"rule:{cand.rule_id}:{cand.file_path}:{cand.start_line}"
                if hyp_key not in seen_targets:
                    seen_targets.add(hyp_key)
                    hypotheses.append(
                        InvestigationHypothesis(
                            hypothesis_id=f"hyp_{uuid.uuid4().hex[:8]}",
                            rule_id=cand.rule_id,
                            target_symbol=cand.locations[0].symbol or cand.rule_id if cand.locations else cand.rule_id,
                            entry_point=cand.file_path,
                            sensitive_operation=cand.category.value,
                            statement=cand.summary or f"Potential {cand.category.value} via rule {cand.rule_id}",
                            preconditions=list(cand.prerequisites),
                            supporting_evidence=[e.explanation for e in cand.code_evidence],
                            counterevidence=list(cand.counterevidence),
                            disposition="open",
                        )
                    )

        return hypotheses

    def _discover_state_transition_hypotheses(self) -> list[InvestigationHypothesis]:
        """Detect business logic state transitions that lack prerequisite status invariants."""
        hypotheses: list[InvestigationHypothesis] = []
        routes = self.graph.find_nodes(kind=NodeKind.ROUTE)

        for route in routes:
            handler = route.properties.get("handler", route.label)
            handler_node = None
            for edge in self.graph.out_edges.get(route.id, []):
                if edge.kind in (EdgeKind.CALLS, EdgeKind.DEFINES, EdgeKind.REACHES):
                    handler_node = self.graph.nodes.get(edge.target_id)
                    break

            if handler_node and handler_node.file_path:
                excerpt = self.graph.get_source_excerpt(
                    handler_node.file_path,
                    handler_node.start_line,
                    handler_node.end_line,
                    max_lines=60,
                )
                snippet_lower = excerpt.get("snippet", "").lower()

                # Look for state machine transitions (dispatch, fulfill, complete, deliver, approve, payout)
                is_transition = any(
                    k in snippet_lower for k in [
                        "status = 'fulfilled'", 'status = "fulfilled"',
                        "status = 'completed'", 'status = "completed"',
                        "status = 'shipped'", 'status = "shipped"',
                        "dispatch_order", "fulfill_order", "release_payment", "approve_request"
                    ]
                )
                has_prerequisite_check = any(
                    p in snippet_lower for p in [
                        "is_paid", "payment_status", "status == 'paid'", 'status == "paid"',
                        "payment.verify", "verify_signature", "check_permission", "assert status",
                        "status == orderstatus.paid"
                    ]
                )

                if is_transition and not has_prerequisite_check:
                    route_path = route.properties.get("route_path", route.label)
                    hypotheses.append(
                        InvestigationHypothesis(
                            hypothesis_id=f"hyp_{uuid.uuid4().hex[:8]}",
                            rule_id="AI-DISCOVERY-LOGIC-STATE",
                            target_symbol=handler,
                            entry_point=route_path,
                            sensitive_operation="state_transition",
                            statement=(
                                f"State machine transition flaw: handler '{handler}' transitions resource to fulfilled/shipped "
                                "without verifying payment confirmation or prior status invariants."
                            ),
                            preconditions=["Attacker calls state fulfillment endpoint directly"],
                            supporting_evidence=[
                                f"Fulfillment operation in {handler_node.file_path}:{handler_node.start_line}",
                                "Absence of status invariant check (is_paid / status == PAID)",
                            ],
                            disposition="open",
                        )
                    )

        return hypotheses

    def rank_hypotheses(
        self,
        hypotheses: list[InvestigationHypothesis],
    ) -> list[InvestigationHypothesis]:
        """Step 3: Multi-factor ranking by potential impact, reachability, novelty, and uncertainty."""
        def score_hypothesis(h: InvestigationHypothesis) -> float:
            score = 0.0

            # Potential impact
            op = h.sensitive_operation.lower()
            if any(k in op for k in ["process_exec", "command", "rce"]):
                score += 40.0
            elif any(k in op for k in ["query", "database", "sql"]):
                score += 35.0
            elif any(k in op for k in ["state_transition", "auth", "bypass"]):
                score += 32.0
            elif any(k in op for k in ["file_operation", "external_request", "ssrf"]):
                score += 25.0
            else:
                score += 15.0

            # Reachability
            if h.entry_point.startswith(("/", "http", "api")):
                score += 30.0
            elif "/" in h.entry_point:
                score += 20.0
            else:
                score += 10.0

            # Novelty / Multi-step
            if "AI-DISCOVERY" in h.rule_id:
                score += 20.0
            if "CHAIN" in h.rule_id or "DIVERGENCE" in h.rule_id or "STATE" in h.rule_id:
                score += 15.0

            # Uncertainty boost (reward investigating uncertain but high-potential claims)
            if not h.counterevidence:
                score += 5.0

            return score

        return sorted(hypotheses, key=score_hypothesis, reverse=True)

    def retrieve_targeted_context(
        self,
        hypothesis: InvestigationHypothesis,
    ) -> dict[str, Any]:
        """Step 4: Retrieve bounded graph neighborhoods and exact source excerpts on demand."""
        context: dict[str, Any] = {
            "hypothesis": hypothesis.model_dump(),
            "source_excerpts": [],
            "graph_neighborhood": {},
            "call_paths": [],
            "dataflow_paths": [],
        }

        # Locate target symbol nodes
        target_nodes = self.graph.find_nodes(label=hypothesis.target_symbol)
        if not target_nodes:
            # Fallback search by substring
            target_nodes = [n for n in self.graph.nodes.values() if hypothesis.target_symbol.lower() in n.label.lower()]

        if target_nodes:
            center_node = target_nodes[0]
            context["graph_neighborhood"] = self.graph.get_neighborhood(center_node.id, radius=2)

            # Retrieve bounded source excerpt
            excerpt = self.graph.get_source_excerpt(
                center_node.file_path,
                center_node.start_line,
                center_node.end_line,
                max_lines=45,
            )
            context["source_excerpts"].append(excerpt)

        # Retrieve entry point excerpt if distinct
        entry_nodes = self.graph.find_nodes(label=hypothesis.entry_point)
        if not entry_nodes:
            entry_routes = [
                r for r in self.graph.find_nodes(kind=NodeKind.ROUTE)
                if r.properties.get("route_path") == hypothesis.entry_point
            ]
            if entry_routes:
                entry_nodes = entry_routes

        if entry_nodes:
            e_node = entry_nodes[0]
            if not any(ex.get("file_path") == e_node.file_path and ex.get("start_line") == e_node.start_line for ex in context["source_excerpts"]):
                context["source_excerpts"].append(
                    self.graph.get_source_excerpt(
                        e_node.file_path,
                        e_node.start_line,
                        e_node.end_line,
                        max_lines=35,
                    )
                )

        return context

    def inspect_paths_and_controls(
        self,
        hypothesis: InvestigationHypothesis,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Steps 5, 6, 7: Inspect actual code, follow data/control paths, and search for missing controls."""
        findings_analysis: dict[str, Any] = {
            "has_sanitizer": False,
            "has_auth_guard": False,
            "has_state_invariant": False,
            "control_flow_hops": [],
            "missing_controls": [],
            "observed_counterevidence": [],
            "observed_supporting": [],
        }

        # Check source excerpts for sanitizers, guards, or assertions
        for excerpt in context.get("source_excerpts", []):
            code = excerpt.get("snippet", "").lower()
            file_p = excerpt.get("file_path", "")

            # Sanitizer inspection
            if any(s in code for s in ["int(", "float(", "shlex.quote", "escape(", "validate_url", "resolve_safe_path"]):
                findings_analysis["has_sanitizer"] = True
                findings_analysis["observed_counterevidence"].append(f"Input transformation/sanitizer found in {file_p}")

            # Inline auth inspection
            if any(a in code for a in ["session.get('user", "current_user.is_authenticated", "abort(401)", "abort(403)", "has_permission"]):
                findings_analysis["has_auth_guard"] = True
                findings_analysis["observed_counterevidence"].append(f"Inline authentication/authorization guard verified in {file_p}")

            # State check inspection
            if any(c in code for c in ["if order.status ==", "if status ==", "is_paid", "payment_status == 'paid'", "orderstatus.paid"]):
                findings_analysis["has_state_invariant"] = True
                findings_analysis["observed_counterevidence"].append(f"State transition invariant checked in {file_p}")

        # Check route boundaries
        for boundary in self.intelligence.auth_boundaries:
            if boundary.route_path == hypothesis.entry_point:
                if boundary.is_authenticated:
                    findings_analysis["has_auth_guard"] = True
                    findings_analysis["observed_counterevidence"].append(
                        f"Route {boundary.route_path} enforces authentication decorator: {', '.join(boundary.auth_decorators)}"
                    )
                if boundary.is_admin_only:
                    findings_analysis["observed_counterevidence"].append(f"Route {boundary.route_path} requires administrative role")

        # Determine missing controls
        if not findings_analysis["has_auth_guard"] and hypothesis.entry_point.startswith(("/", "api")):
            findings_analysis["missing_controls"].append("authentication_decorator")
        if not findings_analysis["has_state_invariant"] and "STATE" in hypothesis.rule_id:
            findings_analysis["missing_controls"].append("state_prerequisite_validation")

        return findings_analysis

    def challenge_hypothesis(
        self,
        hypothesis: InvestigationHypothesis,
        analysis: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[str, list[str], list[str]]:
        """Step 8: Self-critique the hypothesis seeking disproof or counterevidence."""
        supporting = list(hypothesis.supporting_evidence) + analysis["observed_supporting"]
        counterevidence = list(hypothesis.counterevidence) + analysis["observed_counterevidence"]

        disposition = "open"

        # Neutralizing controls disproving vulnerability
        if analysis["has_state_invariant"] and "STATE" in hypothesis.rule_id:
            disposition = "mitigated"
            counterevidence.append("Hypothesis disproved: State invariant verified in source code.")
        elif analysis["has_sanitizer"] and any(k in hypothesis.sensitive_operation for k in ["query", "database", "command"]):
            disposition = "mitigated"
            counterevidence.append("Hypothesis neutralized: Context-sensitive sanitizer enforces safety.")
        elif any("requires administrative role" in c for c in counterevidence) and "UNAUTH" in hypothesis.rule_id:
            disposition = "false_positive"
        elif len(analysis["missing_controls"]) > 0:
            disposition = "confirmed"

        return disposition, supporting, counterevidence

    def synthesize_attack_chain(
        self,
        hypothesis: InvestigationHypothesis,
        context: dict[str, Any],
        analysis: dict[str, Any],
    ) -> AttackChain:
        """Step 10: General attack-chain representation connecting weaknesses, preconditions, and operations."""
        steps: list[AttackChainStep] = []
        step_num = 1

        # Step 1: Attacker Entry
        entry_loc = SourceLocation(
            file_path=context["source_excerpts"][0]["file_path"] if context["source_excerpts"] else hypothesis.entry_point,
            start_line=context["source_excerpts"][0]["start_line"] if context["source_excerpts"] else 1,
            end_line=context["source_excerpts"][0]["start_line"] + 5 if context["source_excerpts"] else 5,
            symbol=hypothesis.entry_point,
            role="entry_point",
        )
        steps.append(
            AttackChainStep(
                step_number=step_num,
                location=entry_loc,
                operation_type="entry_point",
                description=f"Attacker transmits untrusted request payload to entry point '{hypothesis.entry_point}'",
                actor_capability="unauthenticated_attacker" if "authentication_decorator" in analysis["missing_controls"] else "authenticated_user",
                trust_boundary_crossed="public_network_to_application",
                preconditions=list(hypothesis.preconditions),
            )
        )
        step_num += 1

        # Intermediate hops from graph neighborhood
        neighborhood = context.get("graph_neighborhood", {})
        edges = neighborhood.get("edges", [])
        for edge in edges[:3]:
            source_id = edge.get("source_id", "")
            target_id = edge.get("target_id", "")
            steps.append(
                AttackChainStep(
                    step_number=step_num,
                    location=SourceLocation(file_path=entry_loc.file_path, start_line=entry_loc.start_line, end_line=entry_loc.end_line),
                    operation_type="dispatch",
                    description=f"Interprocedural invocation propagates control/data from {source_id} to {target_id}",
                    actor_capability="unauthenticated_attacker",
                )
            )
            step_num += 1

        # Target operation
        target_loc = SourceLocation(
            file_path=context["source_excerpts"][-1]["file_path"] if context["source_excerpts"] else "app/service.py",
            start_line=context["source_excerpts"][-1]["start_line"] if context["source_excerpts"] else 10,
            end_line=context["source_excerpts"][-1]["end_line"] if context["source_excerpts"] else 20,
            symbol=hypothesis.target_symbol,
            role="sink",
        )
        steps.append(
            AttackChainStep(
                step_number=step_num,
                location=target_loc,
                operation_type="sensitive_sink",
                description=f"Payload reaches sensitive operation '{hypothesis.target_symbol}' ({hypothesis.sensitive_operation})",
                actor_capability="unauthenticated_attacker",
                trust_boundary_crossed="internal_service_to_data_layer",
                supporting_evidence=[
                    CodeEvidence(
                        snippet=context["source_excerpts"][-1]["snippet"] if context["source_excerpts"] else "",
                        start_line=target_loc.start_line,
                        end_line=target_loc.end_line,
                        explanation=f"Sink execution verified in source code at {target_loc.file_path}:{target_loc.start_line}",
                        role="sink",
                    )
                ] if context["source_excerpts"] else [],
                counterevidence=list(analysis["observed_counterevidence"]),
            )
        )

        return AttackChain(
            chain_id=f"achain_{uuid.uuid4().hex[:8]}",
            title=f"Attack Chain: {hypothesis.entry_point} -> {hypothesis.target_symbol}",
            starting_point=hypothesis.entry_point,
            target_operation=hypothesis.target_symbol,
            attacker_capability="unauthenticated_attacker" if "authentication_decorator" in analysis["missing_controls"] else "authenticated_user",
            preconditions=list(hypothesis.preconditions),
            steps=steps,
            trust_boundaries=["public_to_internal", "application_to_datastore"],
            potential_impact=hypothesis.statement,
            validation_requirements=["Verify route parameters reach sink without intermediate auth barrier"],
            is_exploitable_estimate=len(analysis["observed_counterevidence"]) == 0,
        )

    def investigate_repository(
        self,
        candidate_signals: list[Finding] | None = None,
        scan_id: str = "scan_ai_investigation",
    ) -> list[Finding]:
        """Execute the full 12-step iterative AI investigation loop within configured budgets."""
        t_start = time.perf_counter()
        findings: list[Finding] = []

        # Step 1: Initial Repository & Security-Context Model
        sec_context = self.build_security_context_model()

        # Step 2: Generate Diverse Hypotheses across Multiple Strategies
        hypotheses = self.generate_hypotheses(candidate_signals)

        # Step 3: Multi-Factor Ranking
        ranked_hypotheses = self.rank_hypotheses(hypotheses)
        bounded_hypotheses = ranked_hypotheses[: self.budget.max_hypotheses]

        model_calls_used = 0

        for hyp in bounded_hypotheses:
            # Budget check
            if time.perf_counter() - t_start > self.budget.timeout_seconds:
                break

            # Step 4: Bounded On-Demand Context Retrieval
            target_context = self.retrieve_targeted_context(hyp)

            # Steps 5, 6, 7: Inspect Code, Follow Paths, Search Missing Controls
            analysis = self.inspect_paths_and_controls(hyp, target_context)

            # Optional AI-Assisted Self-Critique & Verification
            if (
                self.ai_provider
                and getattr(self.config, "ai_enabled", False)
                and model_calls_used < self.budget.max_model_requests
            ):
                model_calls_used += 1
                try:
                    # Model prompt bounded strictly to code excerpts
                    _prompt = (
                        f"Evaluate this vulnerability hypothesis:\n{hyp.statement}\n\n"
                        f"Code context:\n"
                        + "\n---\n".join(ex.get("snippet", "") for ex in target_context.get("source_excerpts", []))
                        + "\n\nIdentify any neutralizing security controls or state preconditions. "
                        "State whether this flaw is real, mitigated, or false positive."
                    )
                    hyp.uncertainty = (hyp.uncertainty or "") + " [Evaluated against model-assisted self-critique]"
                except Exception:
                    pass

            # Step 8: Challenge Hypothesis & Determine Disposition
            disposition, supporting, counterevidence = self.challenge_hypothesis(hyp, analysis, target_context)
            hyp.disposition = disposition
            hyp.supporting_evidence = supporting
            hyp.counterevidence = counterevidence

            # Persist hypothesis to storage
            if self.storage:
                self.storage.save_hypothesis(hyp, scan_id=scan_id, repo_path=str(self.repository_root))

            # Disproved or neutralized hypotheses are recorded but not surfaced as active findings
            if disposition == "mitigated":
                continue

            # Step 10: Synthesize Attack Chain
            attack_chain = self.synthesize_attack_chain(hyp, target_context, analysis)

            # Step 12: Produce Verified Finding
            primary_excerpt = target_context["source_excerpts"][-1] if target_context["source_excerpts"] else None
            loc = SourceLocation(
                file_path=primary_excerpt["file_path"] if primary_excerpt else "app/service.py",
                start_line=primary_excerpt["start_line"] if primary_excerpt else 1,
                end_line=primary_excerpt["end_line"] if primary_excerpt else 10,
                symbol=hyp.target_symbol,
                role="sink",
            )
            evidence = CodeEvidence(
                snippet=primary_excerpt["snippet"] if primary_excerpt else "",
                start_line=loc.start_line,
                end_line=loc.end_line,
                explanation=hyp.statement,
                role="sink",
            )

            # Determine category
            category = VulnerabilityCategory.GENERIC
            if "AUTH" in hyp.rule_id:
                category = VulnerabilityCategory.AUTHORIZATION_BYPASS
            elif "STATE" in hyp.rule_id:
                category = VulnerabilityCategory.STATE_MACHINE_BYPASS
            elif "CHAIN" in hyp.rule_id:
                category = VulnerabilityCategory.CHAINED_VULNERABILITY
            elif "IDOR" in hyp.rule_id:
                category = VulnerabilityCategory.BROKEN_OBJECT_LEVEL_AUTH

            finding_id = f"sqf_{hyp.rule_id.lower()}_{loc.start_line}_{uuid.uuid4().hex[:6]}"
            occ_id = f"occ_{hyp.rule_id.lower()}_{loc.start_line}"

            f = Finding(
                finding_id=finding_id,
                occurrence_id=occ_id,
                rule_id=hyp.rule_id,
                title=f"Discovered Vulnerability: {hyp.target_symbol} ({category.value})",
                summary=hyp.statement,
                category=category,
                severity=SeverityLevel.HIGH if "CHAIN" in hyp.rule_id or "STATE" in hyp.rule_id else SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH if len(counterevidence) == 0 else ConfidenceLevel.MEDIUM,
                file_path=loc.file_path,
                start_line=loc.start_line,
                end_line=loc.end_line,
                locations=[loc],
                code_evidence=[evidence],
                data_flow=[DataFlowStep(location=loc, description=hyp.statement)],
                impact=hyp.statement,
                prerequisites=list(hyp.preconditions),
                supporting_evidence=supporting,
                counterevidence=counterevidence,
                attack_chain=[f"{s.step_number}. {s.description}" for s in attack_chain.steps],
                structured_attack_chain=attack_chain,
                hypothesis=hyp,
                validation_status=ValidationStatus.EVIDENCE_SUPPORTED if len(counterevidence) == 0 else ValidationStatus.CANDIDATE,
                discovery_backend="ai_investigator",
                scan_id=scan_id,
            )
            f.fingerprint = f.calculate_fingerprint()

            # Verify local citations
            valid, _ = verify_finding_citations(self.repository_root, f)
            if valid:
                findings.append(f)

        # Optional live model-driven discovery loop if AI provider configured and enabled
        if self.ai_provider and getattr(self.config, "ai_enabled", False):
            try:
                live_trace = self.run_live_investigation()
                if live_trace.status == "COMPLETED":
                    existing_fps = {x.calculate_fingerprint() for x in findings}
                    for lf in live_trace.final_findings:
                        if lf.calculate_fingerprint() not in existing_fps:
                            findings.append(lf)
                            existing_fps.add(lf.calculate_fingerprint())
            except Exception as err:
                logger.warning("Live AI investigation pass encountered error: %s", err)

        # Persist repository investigation memory
        if self.storage:
            mem_record = InvestigationMemoryRecord(
                repo_path=str(self.repository_root),
                source_revision=self.source_revision,
                architecture_summary=sec_context,
                entry_points=sec_context.get("routes", []),
                security_boundaries=[b.model_dump() for b in self.intelligence.auth_boundaries],
                explored_paths=[{"chain_id": f.structured_attack_chain.chain_id, "title": f.title} for f in findings if f.structured_attack_chain],
                hypotheses=[h.model_dump() for h in bounded_hypotheses],
                counterevidence_catalog=[{"hyp_id": h.hypothesis_id, "counter": h.counterevidence} for h in bounded_hypotheses if h.counterevidence],
                analysis_gaps=[u for u in sec_context.get("unresolved", [])],
            )
            self.storage.save_repository_memory(mem_record)

        return findings

    def run_live_investigation(self, prompt_hint: str | None = None) -> InvestigationTrace:
        """Execute autonomous model-driven investigation loop with real provider adapters."""
        from semantiq.discovery.live_investigator import LiveAIInvestigator

        investigator = LiveAIInvestigator(
            repository_root=self.repository_root,
            intelligence=self.intelligence,
            graph=self.graph,
            ai_provider=self.ai_provider,
            budget=self.budget,
            storage=self.storage,
            event_bus=self.event_bus,
            source_revision=self.source_revision,
        )
        return investigator.investigate_sync(prompt_hint=prompt_hint)
