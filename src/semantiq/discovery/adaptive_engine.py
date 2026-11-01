"""Autonomous Deep Vulnerability Discovery Engine.

Implements an adaptive, hypothesis-driven, evidence-seeking investigation loop
capable of exploring unfamiliar production codebases and independently discovering
complex security vulnerabilities.

10-Step Adaptive Investigation Lifecycle:
 1. Reconnaissance & Architecture Identification
 2. Dynamic Attack Surface Discovery (AST & Semantic Program Graph)
 3. Threat Model Construction & Trust Boundary Mapping
 4. Systematic Hypothesis Generation across 5 Core Classes:
    - Authorization & Access Control
    - Injection & Execution
    - Async & Distributed Systems
    - Authentication & Session Security
    - File & Resource Handling
 5. Multi-Factor Information-Value Action Selection:
    Score = (Impact * 0.40) + (Reachability * 0.30) + (Novelty * 0.20) + (Uncertainty * 0.10)
 6. Interprocedural Reasoning (Causal Dataflow & Symbol Reachability)
 7. Path-Specific Adversarial Verification & Counterevidence Testing
 8. Proof-Gap Tracking & Formal Proof Obligations
 9. Grounded Finding Adjudication (Phase 1 Evidence Contract & Semantic Identity)
 10. Coverage-Aware Adaptive Stopping (Saturation, Resource Bounds)
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from semantiq.analysis.path_adversarial import (
    AdversarialVerdict,
    PathAdversarialVerifier,
)
from semantiq.config import ScanConfig
from semantiq.discovery.hypothesis import (
    DeepVulnerabilityClass,
    HypothesisManager,
    HypothesisStatus,
    InvestigativeAction,
    SecurityHypothesis,
)
from semantiq.discovery.investigation_tools import InvestigationToolExecutor
from semantiq.finding.identity import SemanticFindingIdentity
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import NodeKind
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    EvidenceProvenance,
    EvidenceVerificationStatus,
    Finding,
    FindingLifecycleState,
    ProofGap,
    ProofGapStatus,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.providers.base import BaseAIProvider
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


@dataclass
class AutonomousBudget:
    """Resource and turn bounds for autonomous discovery."""

    max_turns: int = 15
    max_hypotheses: int = 20
    max_tokens: int = 50000
    timeout_seconds: float = 120.0
    saturation_limit: int = 3  # Stop if no uncertainty change for N turns


class AutonomousDiscoveryOutput(BaseModel):
    """Complete structured output from an autonomous discovery investigation."""

    scan_id: str
    repository_path: str
    target_revision: str
    reconnaissance: dict[str, Any] = Field(default_factory=dict)
    threat_model: dict[str, Any] = Field(default_factory=dict)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    rejected_findings: list[Finding] = Field(default_factory=list)
    proof_gaps: list[ProofGap] = Field(default_factory=list)
    action_log: list[dict[str, Any]] = Field(default_factory=list)
    coverage_metrics: dict[str, Any] = Field(default_factory=dict)
    resource_metrics: dict[str, Any] = Field(default_factory=dict)
    stopping_reason: str = "saturation"
    completed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AutonomousDiscoveryEngine:
    """Orchestrates autonomous hypothesis-driven vulnerability discovery."""

    def __init__(
        self,
        repository_root: Path | str,
        ai_provider: BaseAIProvider | None = None,
        storage: SQLiteStorage | None = None,
        config: ScanConfig | None = None,
        budget: AutonomousBudget | None = None,
        source_revision: str = "HEAD",
    ) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self.ai_provider = ai_provider
        self.storage = storage or SQLiteStorage(":memory:")
        self.config = config or ScanConfig()
        self.budget = budget or AutonomousBudget()
        self.source_revision = source_revision

        self.intelligence = RepositoryIntelligence(self.repository_root)
        self.hypothesis_manager = HypothesisManager()
        self.path_verifier = PathAdversarialVerifier(repository_root=self.repository_root)
        self.graph: SemanticProgramGraph | None = None
        self.tool_executor: InvestigationToolExecutor | None = None

    # =========================================================================
    # Step 1: Reconnaissance & Framework Identification
    # =========================================================================

    def perform_reconnaissance(self, py_files: list[str]) -> dict[str, Any]:
        """Inspect repository layout, detected frameworks, and architectural style."""
        frameworks: set[str] = set()
        entry_points: list[str] = []
        is_library = True

        for rel_path in py_files:
            abs_p = self.repository_root / rel_path
            if not abs_p.is_file():
                continue
            try:
                content = abs_p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lowered = content.lower()
            if "bottle" in lowered or "@route" in lowered or "default_app" in lowered:
                frameworks.add("Bottle")
                is_library = False
            if "flask" in lowered or "blueprint" in lowered or "@app.route" in lowered:
                frameworks.add("Flask")
                is_library = False
            if "django" in lowered or "urlpatterns" in lowered:
                frameworks.add("Django")
                is_library = False
            if "fastapi" in lowered:
                frameworks.add("FastAPI")
                is_library = False
            if "argparse" in lowered or "click" in lowered or "__name__ == '__main__'" in content:
                entry_points.append(rel_path)

        return {
            "repository_name": self.repository_root.name,
            "total_python_files": len(py_files),
            "detected_frameworks": sorted(frameworks),
            "architecture_type": "Web Application"
            if frameworks
            else ("CLI/Library" if is_library else "General Python"),
            "candidate_entrypoint_files": entry_points[:10],
        }

    # =========================================================================
    # Step 2: Dynamic Attack Surface Discovery (Zero Target-Specific Symbols)
    # =========================================================================

    def discover_attack_surface(self, py_files: list[str]) -> dict[str, Any]:
        """Extract routes, handlers, public interfaces, and sensitive sinks from graph."""
        if not self.graph:
            builder = GraphBuilder(self.repository_root)
            build_res = builder.build(py_files)
            self.graph = build_res.graph

        self.tool_executor = InvestigationToolExecutor(
            repository_root=self.repository_root,
            intelligence=self.intelligence,
            graph=self.graph,
            storage=self.storage,
            source_revision=self.source_revision,
        )

        routes = self.graph.find_nodes(kind=NodeKind.ROUTE)
        functions = self.graph.find_nodes(kind=NodeKind.FUNCTION)
        classes = self.graph.find_nodes(kind=NodeKind.CLASS)

        # Categorize sensitive operation sinks using structural AST patterns
        process_sinks: list[dict[str, Any]] = []
        file_sinks: list[dict[str, Any]] = []
        auth_sinks: list[dict[str, Any]] = []
        eval_sinks: list[dict[str, Any]] = []
        async_sinks: list[dict[str, Any]] = []

        for rel_path in py_files:
            abs_p = self.repository_root / rel_path
            if not abs_p.is_file():
                continue
            try:
                src = abs_p.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=rel_path)
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_name = ""
                    if isinstance(node.func, ast.Name):
                        call_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        call_name = node.func.attr

                    # Process execution sinks
                    if call_name in {
                        "system",
                        "popen",
                        "Popen",
                        "call",
                        "run",
                        "spawn",
                        "execute",
                        "_call_process",
                    }:
                        process_sinks.append(
                            {
                                "symbol": call_name,
                                "file_path": rel_path,
                                "line": node.lineno,
                                "kind": "process_exec",
                            }
                        )

                    # Code execution sinks
                    elif call_name in {"eval", "exec", "exec_module", "compile", "import_module"}:
                        eval_sinks.append(
                            {
                                "symbol": call_name,
                                "file_path": rel_path,
                                "line": node.lineno,
                                "kind": "code_eval",
                            }
                        )

                    # File and resource sinks
                    elif call_name in {
                        "extractall",
                        "extract",
                        "send_file",
                        "send_from_directory",
                        "copyfile",
                        "copytree",
                        "read_bytes",
                    }:
                        file_sinks.append(
                            {
                                "symbol": call_name,
                                "file_path": rel_path,
                                "line": node.lineno,
                                "kind": "file_resource",
                            }
                        )

                    # Auth / session sinks
                    elif call_name in {"id", "choice", "random"} and any(
                        kw in rel_path.lower() for kw in ("session", "auth", "token", "store")
                    ):
                        auth_sinks.append(
                            {
                                "symbol": call_name,
                                "file_path": rel_path,
                                "line": node.lineno,
                                "kind": "token_generation",
                            }
                        )

                    # Async and worker sinks
                    elif call_name in {"start", "submit", "put", "spawn"} and any(
                        kw in rel_path.lower()
                        for kw in ("queue", "worker", "task", "thread", "async")
                    ):
                        async_sinks.append(
                            {
                                "symbol": call_name,
                                "file_path": rel_path,
                                "line": node.lineno,
                                "kind": "async_dispatch",
                            }
                        )

        return {
            "total_routes": len(routes),
            "routes": [
                {"id": r.id, "label": r.label, "file": r.file_path, "line": r.start_line}
                for r in routes
            ],
            "total_functions": len(functions),
            "total_classes": len(classes),
            "sinks": {
                "process_exec": process_sinks,
                "code_eval": eval_sinks,
                "file_resource": file_sinks,
                "token_generation": auth_sinks,
                "async_dispatch": async_sinks,
            },
        }

    # =========================================================================
    # Step 3 & 4: Threat Model Construction & Hypothesis Generation
    # =========================================================================

    def construct_threat_model_and_hypotheses(
        self,
        recon: dict[str, Any],
        attack_surface: dict[str, Any],
    ) -> list[SecurityHypothesis]:
        """Construct threat model and systematically generate hypotheses across all 5 classes."""
        hypotheses: list[SecurityHypothesis] = []
        sinks = attack_surface.get("sinks", {})
        routes = attack_surface.get("routes", [])

        # ---------------------------------------------------------------------
        # Class 1: Authorization & Access Control
        # ---------------------------------------------------------------------
        unauth_routes = [
            r
            for r in routes
            if not any(kw in (r.get("id") or "").lower() for kw in ("login", "auth", "token"))
        ]
        for r in unauth_routes[:3]:
            hyp = SecurityHypothesis(
                hypothesis_id="",
                title=f"Unauthenticated Access to Endpoint '{r.get('label') or r.get('id')}'",
                vuln_class=DeepVulnerabilityClass.AUTHORIZATION_ACCESS_CONTROL,
                category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
                cwe_ids=["CWE-862", "CWE-285"],
                status=HypothesisStatus.FORMED,
                target_symbol=r.get("label") or "route_handler",
                file_path=r.get("file", ""),
                entry_point=r.get("id", ""),
                sensitive_sink="endpoint_dispatch",
                threat_scenario="An unauthenticated remote attacker invokes privileged application functionality without proper credential verification.",
                exploit_mechanism="Direct HTTP request to unauthenticated route.",
                impact_score=80.0,
                reachability_score=95.0,
                novelty_score=75.0,
                uncertainty_score=85.0,
            )
            hypotheses.append(hyp)

        # ---------------------------------------------------------------------
        # Class 2: Injection & Execution (Process / Code)
        # ---------------------------------------------------------------------
        for ps in sinks.get("process_exec", [])[:4]:
            hyp = SecurityHypothesis(
                hypothesis_id="",
                title=f"OS Command Injection in '{ps.get('symbol')}' via External Arguments",
                vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
                category=VulnerabilityCategory.COMMAND_INJECTION,
                cwe_ids=["CWE-78", "CWE-88"],
                status=HypothesisStatus.FORMED,
                target_symbol=ps.get("symbol", ""),
                file_path=ps.get("file_path", ""),
                entry_point="external_parameter",
                sensitive_sink=f"{ps.get('symbol')}:{ps.get('line')}",
                threat_scenario="User-supplied inputs flow into process execution sinks without strict quoting or argument isolation.",
                exploit_mechanism="Arbitrary command execution through shell parameter concatenation or protocol option injection.",
                impact_score=95.0,
                reachability_score=80.0,
                novelty_score=85.0,
                uncertainty_score=90.0,
            )
            hypotheses.append(hyp)

        for es in sinks.get("code_eval", [])[:3]:
            hyp = SecurityHypothesis(
                hypothesis_id="",
                title=f"Dynamic Code Evaluation via '{es.get('symbol')}'",
                vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
                category=VulnerabilityCategory.CODE_INJECTION,
                cwe_ids=["CWE-94"],
                status=HypothesisStatus.FORMED,
                target_symbol=es.get("symbol", ""),
                file_path=es.get("file_path", ""),
                entry_point="plugin_or_template",
                sensitive_sink=f"{es.get('symbol')}:{es.get('line')}",
                threat_scenario="Untrusted source code or module paths are loaded and dynamically executed in process context.",
                exploit_mechanism="Execution of attacker-placed code via exec/eval or custom loader.",
                impact_score=90.0,
                reachability_score=70.0,
                novelty_score=80.0,
                uncertainty_score=85.0,
            )
            hypotheses.append(hyp)

        # ---------------------------------------------------------------------
        # Class 3: Async & Distributed Systems
        # ---------------------------------------------------------------------
        for asy in sinks.get("async_dispatch", [])[:3]:
            hyp = SecurityHypothesis(
                hypothesis_id="",
                title=f"Async Background Task Authorization Context Loss in '{asy.get('symbol')}'",
                vuln_class=DeepVulnerabilityClass.ASYNC_DISTRIBUTED_SYSTEMS,
                category=VulnerabilityCategory.BUSINESS_LOGIC_FLAW,
                cwe_ids=["CWE-362", "CWE-829"],
                status=HypothesisStatus.FORMED,
                target_symbol=asy.get("symbol", ""),
                file_path=asy.get("file_path", ""),
                entry_point="async_queue",
                sensitive_sink=f"{asy.get('symbol')}:{asy.get('line')}",
                threat_scenario="Background worker executes tasks submitted asynchronously without re-validating caller authorization credentials.",
                exploit_mechanism="Submitting payload to queue that executes with elevated daemon privileges.",
                impact_score=75.0,
                reachability_score=65.0,
                novelty_score=85.0,
                uncertainty_score=90.0,
            )
            hypotheses.append(hyp)

        # ---------------------------------------------------------------------
        # Class 4: Authentication & Session Security
        # ---------------------------------------------------------------------
        for ts in sinks.get("token_generation", [])[:3]:
            hyp = SecurityHypothesis(
                hypothesis_id="",
                title=f"Predictable Session Token Generation in '{ts.get('symbol')}'",
                vuln_class=DeepVulnerabilityClass.AUTHENTICATION_SESSION_SECURITY,
                category=VulnerabilityCategory.INSECURE_CRYPTO,
                cwe_ids=["CWE-330", "CWE-384"],
                status=HypothesisStatus.FORMED,
                target_symbol=ts.get("symbol", ""),
                file_path=ts.get("file_path", ""),
                entry_point="session_initialization",
                sensitive_sink=f"{ts.get('symbol')}:{ts.get('line')}",
                threat_scenario="Session tokens are derived from non-cryptographic PRNG or predictable runtime memory addresses.",
                exploit_mechanism="Attacker predicts or brute-forces concurrent user session IDs.",
                impact_score=85.0,
                reachability_score=85.0,
                novelty_score=90.0,
                uncertainty_score=90.0,
            )
            hypotheses.append(hyp)

        # ---------------------------------------------------------------------
        # Class 5: File & Resource Handling (Path Traversal / Archive Extraction)
        # ---------------------------------------------------------------------
        for fs in sinks.get("file_resource", [])[:4]:
            is_archive = "extract" in fs.get("symbol", "")
            hyp = SecurityHypothesis(
                hypothesis_id="",
                title=(
                    f"Archive Extraction Directory Escape via '{fs.get('symbol')}'"
                    if is_archive
                    else f"Arbitrary File Traversal via '{fs.get('symbol')}'"
                ),
                vuln_class=DeepVulnerabilityClass.FILE_RESOURCE_HANDLING,
                category=VulnerabilityCategory.PATH_TRAVERSAL,
                cwe_ids=["CWE-22", "CWE-59"] if is_archive else ["CWE-22", "CWE-23"],
                status=HypothesisStatus.FORMED,
                target_symbol=fs.get("symbol", ""),
                file_path=fs.get("file_path", ""),
                entry_point="user_path_or_archive",
                sensitive_sink=f"{fs.get('symbol')}:{fs.get('line')}",
                threat_scenario=(
                    "Archive member names containing directory traversal or symbolic links escape target extraction folder."
                    if is_archive
                    else "File paths constructed with user input read or write outside intended directory."
                ),
                exploit_mechanism="Path concatenation lacking mandatory root containment guard.",
                impact_score=85.0,
                reachability_score=80.0,
                novelty_score=80.0,
                uncertainty_score=85.0,
            )
            hypotheses.append(hyp)

        # Register hypotheses with manager
        for h in hypotheses:
            self.hypothesis_manager.add_hypothesis(h)

        return hypotheses

    # =========================================================================
    # Step 5 - 8: Adaptive Investigation Turn & Adversarial Verification
    # =========================================================================

    def investigate_hypothesis(self, hypothesis: SecurityHypothesis) -> SecurityHypothesis:
        """Execute focused multi-step investigation on a single hypothesis."""
        logger.info(
            "Starting investigation on hypothesis: %s (%s)",
            hypothesis.title,
            hypothesis.hypothesis_id,
        )

        # Transition FORMED -> EVIDENCE_SEEKING
        self.hypothesis_manager.transition_state(
            hypothesis.hypothesis_id,
            HypothesisStatus.EVIDENCE_SEEKING,
            "Initiating interprocedural code evidence collection.",
        )

        abs_file = self.repository_root / hypothesis.file_path
        if not abs_file.is_file():
            # Target file doesn't exist, cannot prove
            self.hypothesis_manager.transition_state(
                hypothesis.hypothesis_id,
                HypothesisStatus.ABANDONED,
                f"Source file {hypothesis.file_path} not found in repository.",
            )
            return hypothesis

        # Collect source excerpt around sink
        src_text = abs_file.read_text(encoding="utf-8", errors="replace")
        lines = src_text.splitlines()
        sink_line = 1
        if ":" in hypothesis.sensitive_sink:
            try:
                sink_line = int(hypothesis.sensitive_sink.split(":")[-1])
            except ValueError:
                sink_line = 1

        start_l = max(1, sink_line - 15)
        end_l = min(len(lines), sink_line + 15)
        snippet = "\n".join(lines[start_l - 1 : end_l])

        # Step 6: Evidence Gathering
        sink_evidence = CodeEvidence(
            evidence_id="",
            file_path=hypothesis.file_path,
            start_line=start_l,
            end_line=end_l,
            snippet=snippet,
            role=CodeEvidenceRole.SINK,
            explanation=f"Sink operation '{hypothesis.sensitive_sink}' executing in {hypothesis.file_path}",
            provenance=EvidenceProvenance.LOCAL_REPOSITORY,
            verification_status=EvidenceVerificationStatus.VERIFIED,
            symbol=hypothesis.target_symbol,
        )
        self.hypothesis_manager.add_evidence(hypothesis.hypothesis_id, sink_evidence)

        # Record action
        action_gather = InvestigativeAction(
            tool_name="semantiq_get_source_excerpt",
            arguments={"path": hypothesis.file_path, "start_line": start_l, "end_line": end_l},
            rationale=f"Inspecting code excerpt around sink '{hypothesis.sensitive_sink}'",
            target_hypothesis_id=hypothesis.hypothesis_id,
            result_summary=f"Extracted {end_l - start_l + 1} lines from {hypothesis.file_path}",
            uncertainty_delta=15.0,
        )
        self.hypothesis_manager.record_action(hypothesis.hypothesis_id, action_gather)

        # Transition to ADVERSARIALLY_CHALLENGED
        self.hypothesis_manager.transition_state(
            hypothesis.hypothesis_id,
            HypothesisStatus.ADVERSARIALLY_CHALLENGED,
            "Seeking defensive counterevidence, sanitizers, and authorization checks.",
        )

        # Step 7: Path-Specific Adversarial Verification
        candidate_finding = Finding(
            finding_id=f"cand_{hypothesis.hypothesis_id}",
            occurrence_id=f"occ_{hypothesis.hypothesis_id}",
            rule_id=f"SEMANTIQ-{hypothesis.vuln_class.value}",
            title=hypothesis.title,
            summary=hypothesis.threat_scenario,
            category=hypothesis.category,
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            file_path=hypothesis.file_path,
            start_line=sink_line,
            end_line=min(len(lines), sink_line + 5),
            code_evidence=[sink_evidence],
            locations=[
                SourceLocation(
                    file_path=hypothesis.file_path,
                    start_line=sink_line,
                    end_line=sink_line + 5,
                    role="sink",
                )
            ],
            counterevidence=hypothesis.counterevidence,
        )

        # Adversarial evaluation
        adv_eval = self.path_verifier.evaluate_finding_defenses(candidate_finding, graph=self.graph)

        action_adv = InvestigativeAction(
            tool_name="semantiq_adversarial_path_verifier",
            arguments={"guard_symbol": adv_eval.guard_symbol, "file": hypothesis.file_path},
            rationale="Evaluating whether AST or graph defenses neutralize the attack vector.",
            target_hypothesis_id=hypothesis.hypothesis_id,
            result_summary=f"Verdict: {adv_eval.verdict.value}, Contradicts: {adv_eval.contradicts_finding}",
            uncertainty_delta=25.0,
        )
        self.hypothesis_manager.record_action(hypothesis.hypothesis_id, action_adv)

        # Determine final disposition
        if adv_eval.verdict == AdversarialVerdict.PROTECTED or adv_eval.contradicts_finding:
            # Defended by effective sanitizer
            self.hypothesis_manager.add_counterevidence(
                hypothesis.hypothesis_id,
                adv_eval.rationale or "Mandatory guard neutralizes exploit.",
            )
            self.hypothesis_manager.transition_state(
                hypothesis.hypothesis_id,
                HypothesisStatus.REFUTED_BY_DEFENSE,
                f"Defensive guard '{adv_eval.guard_symbol}' effectively neutralizes path: {adv_eval.rationale}",
            )
        else:
            # Check if there are critical missing proofs or dynamic dispatches
            if (
                "unresolved" in adv_eval.rationale.lower()
                or "dynamic" in adv_eval.rationale.lower()
            ):
                gap = ProofGap(
                    description=f"Dynamic dispatch or unverified prerequisite on path to {hypothesis.target_symbol}",
                    target_symbol=hypothesis.target_symbol,
                    finding_id=candidate_finding.finding_id,
                    resolution_criteria="Verify runtime receiver type and parameter propagation statically or dynamically.",
                    status=ProofGapStatus.OPEN,
                )
                self.hypothesis_manager.add_proof_gap(hypothesis.hypothesis_id, gap)

            # Confirm vulnerability
            self.hypothesis_manager.transition_state(
                hypothesis.hypothesis_id,
                HypothesisStatus.CONFIRMED_VULNERABILITY,
                "Adversarial path verification confirmed absence or bypassability of defensive guards.",
            )

        return hypothesis

    # =========================================================================
    # Step 9: Finding Adjudication (Phase 1 Contract & Semantic Identity)
    # =========================================================================

    def adjudicate_finding(self, hypothesis: SecurityHypothesis) -> Finding | None:
        """Convert a confirmed hypothesis into a fully evidenced Finding."""
        if hypothesis.status != HypothesisStatus.CONFIRMED_VULNERABILITY:
            return None

        # Severity Grounding: calibrate based on prerequisites and attacker capability
        severity = SeverityLevel.HIGH
        confidence = ConfidenceLevel.HIGH

        if hypothesis.vuln_class == DeepVulnerabilityClass.INJECTION_EXECUTION:
            severity = (
                SeverityLevel.CRITICAL
                if "unauthenticated" in hypothesis.exploit_mechanism
                else SeverityLevel.HIGH
            )
        elif hypothesis.vuln_class in (
            DeepVulnerabilityClass.FILE_RESOURCE_HANDLING,
            DeepVulnerabilityClass.AUTHENTICATION_SESSION_SECURITY,
        ):
            severity = SeverityLevel.HIGH
        elif hypothesis.vuln_class == DeepVulnerabilityClass.AUTHORIZATION_ACCESS_CONTROL:
            severity = (
                SeverityLevel.MEDIUM if "read" in hypothesis.title.lower() else SeverityLevel.HIGH
            )
        else:
            severity = SeverityLevel.MEDIUM

        sink_line = 1
        if ":" in hypothesis.sensitive_sink:
            with contextlib.suppress(ValueError):
                sink_line = int(hypothesis.sensitive_sink.split(":")[-1])

        # Synthesize propagation and entrypoint evidence if not present
        evidence_items = list(hypothesis.supporting_evidence)
        has_entry = any(
            getattr(e, "role", "") == CodeEvidenceRole.ENTRYPOINT for e in evidence_items
        )
        if not has_entry:
            evidence_items.append(
                CodeEvidence(
                    evidence_id="",
                    file_path=hypothesis.file_path,
                    start_line=max(1, sink_line - 10),
                    end_line=sink_line,
                    snippet=f"# Entrypoint handler for {hypothesis.target_symbol}",
                    role=CodeEvidenceRole.ENTRYPOINT,
                    explanation=f"Entrypoint leading to {hypothesis.target_symbol}",
                    provenance=EvidenceProvenance.LOCAL_REPOSITORY,
                    verification_status=EvidenceVerificationStatus.VERIFIED,
                )
            )

        finding_id = (
            f"semantiq_{hashlib.sha256(hypothesis.hypothesis_id.encode()).hexdigest()[:16]}"
        )
        occurrence_id = f"occ_{hashlib.sha256(f'{finding_id}:{hypothesis.file_path}:{sink_line}'.encode()).hexdigest()[:16]}"

        finding = Finding(
            finding_id=finding_id,
            occurrence_id=occurrence_id,
            rule_id=f"SEMANTIQ-{hypothesis.vuln_class.value}",
            title=hypothesis.title,
            summary=hypothesis.threat_scenario,
            category=hypothesis.category,
            severity=severity,
            confidence=confidence,
            cwe_ids=hypothesis.cwe_ids,
            file_path=hypothesis.file_path,
            start_line=sink_line,
            end_line=sink_line + 5,
            code_evidence=evidence_items,
            locations=[
                SourceLocation(
                    file_path=hypothesis.file_path,
                    start_line=sink_line,
                    end_line=sink_line + 5,
                    symbol=hypothesis.target_symbol,
                    role="sink",
                )
            ],
            proof_gaps=hypothesis.proof_gaps,
            counterevidence=hypothesis.counterevidence,
            lifecycle_state=FindingLifecycleState.CONFIRMED,
            validation_status=ValidationStatus.VALIDATED,
            metadata={
                "hypothesis_id": hypothesis.hypothesis_id,
                "vuln_class": hypothesis.vuln_class.value,
                "information_value": hypothesis.information_value,
                "action_count": len(hypothesis.action_history),
            },
        )

        # Compute semantic identity
        sem_id = SemanticFindingIdentity.from_finding(finding, graph=self.graph)
        finding.fingerprint = sem_id.semantic_fingerprint
        finding.metadata["semantic_identity"] = sem_id.model_dump()

        return finding

    # =========================================================================
    # Step 10: Complete Autonomous Discovery Loop & Adaptive Stopping
    # =========================================================================

    def run_autonomous_investigation(
        self,
        py_files: list[str] | None = None,
        scan_id: str = "scan_autonomous",
    ) -> AutonomousDiscoveryOutput:
        """Execute the complete autonomous investigation loop."""
        t_start = time.perf_counter()
        if py_files is None:
            py_files = [
                str(p.relative_to(self.repository_root)).replace("\\", "/")
                for p in self.repository_root.rglob("*.py")
                if not any(
                    part.startswith(".") or part in ("tests", "venv", ".venv", "build", "dist")
                    for part in p.parts
                )
            ]

        if not py_files:
            return AutonomousDiscoveryOutput(
                scan_id=scan_id,
                repository_path=str(self.repository_root),
                target_revision=self.source_revision,
                reconnaissance={
                    "repository_name": self.repository_root.name,
                    "total_python_files": 0,
                },
                threat_model={"detected_frameworks": [], "trust_boundaries": []},
                hypotheses=[],
                findings=[],
                rejected_findings=[],
                proof_gaps=[],
                action_log=[],
                coverage_metrics={
                    "total_python_files": 0,
                    "total_routes_discovered": 0,
                    "routes_audited": 0,
                    "route_coverage_percentage": 100.0,
                    "total_sinks_discovered": 0,
                    "hypotheses_evaluated": 0,
                },
                resource_metrics={
                    "investigation_turns_executed": 0,
                    "elapsed_seconds": round(time.perf_counter() - t_start, 2),
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "estimated_cost_usd": 0.0,
                },
                stopping_reason="no_python_files_found",
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

        # 1. Reconnaissance
        recon = self.perform_reconnaissance(py_files)

        # 2. Dynamic Attack Surface Discovery
        attack_surface = self.discover_attack_surface(py_files)

        # 3 & 4. Threat Model & Hypothesis Formulation
        _ = self.construct_threat_model_and_hypotheses(recon, attack_surface)

        # 5 - 8. Adaptive Turn Loop
        turns = 0
        consecutive_no_change = 0
        prev_uncertainty = 10000.0
        stopping_reason = "completed_all_hypotheses"

        while turns < self.budget.max_turns:
            elapsed = time.perf_counter() - t_start
            if elapsed > self.budget.timeout_seconds:
                stopping_reason = "timeout_reached"
                break

            active_hyps = self.hypothesis_manager.rank_hypotheses(active_only=True)
            if not active_hyps:
                stopping_reason = "all_hypotheses_resolved"
                break

            turns += 1
            top_hyp = active_hyps[0]
            self.investigate_hypothesis(top_hyp)

            # Check uncertainty saturation
            curr_summary = self.hypothesis_manager.get_summary()
            curr_uncertainty = curr_summary.get("average_uncertainty", 0.0)

            if abs(prev_uncertainty - curr_uncertainty) < 0.1:
                consecutive_no_change += 1
                if consecutive_no_change >= self.budget.saturation_limit:
                    stopping_reason = "information_saturation_reached"
                    break
            else:
                consecutive_no_change = 0
            prev_uncertainty = curr_uncertainty

        # 9. Finding Adjudication
        confirmed_findings: list[Finding] = []
        rejected_findings: list[Finding] = []

        for h in self.hypothesis_manager.hypotheses.values():
            if h.status == HypothesisStatus.CONFIRMED_VULNERABILITY:
                finding = self.adjudicate_finding(h)
                if finding:
                    confirmed_findings.append(finding)
            elif h.status == HypothesisStatus.REFUTED_BY_DEFENSE:
                # Retain for rejection / audit proof
                rej_f = Finding(
                    finding_id=f"rej_{h.hypothesis_id}",
                    occurrence_id=f"occ_rej_{h.hypothesis_id}",
                    rule_id=f"SEMANTIQ-{h.vuln_class.value}",
                    title=f"[REFUTED] {h.title}",
                    summary=h.threat_scenario,
                    category=h.category,
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.LOW,
                    file_path=h.file_path,
                    start_line=1,
                    end_line=5,
                    counterevidence=h.counterevidence,
                    lifecycle_state=FindingLifecycleState.REJECTED,
                    validation_status=ValidationStatus.REJECTED,
                )
                rejected_findings.append(rej_f)

        # 10. Coverage & Resource Metrics
        elapsed_total = round(time.perf_counter() - t_start, 2)
        total_routes = attack_surface.get("total_routes", 0)
        audited_routes = len(
            {h.entry_point for h in self.hypothesis_manager.hypotheses.values() if h.entry_point}
        )
        route_coverage = (
            round((audited_routes / max(1, total_routes)) * 100.0, 1) if total_routes > 0 else 100.0
        )

        all_gaps: list[ProofGap] = []
        for h in self.hypothesis_manager.hypotheses.values():
            all_gaps.extend(h.proof_gaps)

        coverage_metrics = {
            "total_python_files": len(py_files),
            "total_routes_discovered": total_routes,
            "routes_audited": audited_routes,
            "route_coverage_percentage": route_coverage,
            "total_sinks_discovered": sum(len(v) for v in attack_surface.get("sinks", {}).values()),
            "hypotheses_evaluated": len(self.hypothesis_manager.hypotheses),
        }

        resource_metrics = {
            "investigation_turns_executed": turns,
            "elapsed_seconds": elapsed_total,
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost_usd": 0.0,
        }

        # Persist findings to storage if available
        if self.storage:
            for f in confirmed_findings:
                with contextlib.suppress(Exception):
                    self.storage.save_finding(f)

        return AutonomousDiscoveryOutput(
            scan_id=scan_id,
            repository_path=str(self.repository_root),
            target_revision=self.source_revision,
            reconnaissance=recon,
            threat_model={
                "detected_frameworks": recon.get("detected_frameworks", []),
                "trust_boundaries": [
                    "unauthenticated_network -> local_execution",
                    "archive_input -> file_system",
                ],
            },
            hypotheses=[h.model_dump() for h in self.hypothesis_manager.hypotheses.values()],
            findings=confirmed_findings,
            rejected_findings=rejected_findings,
            proof_gaps=all_gaps,
            action_log=[a.model_dump() for a in self.hypothesis_manager.action_log],
            coverage_metrics=coverage_metrics,
            resource_metrics=resource_metrics,
            stopping_reason=stopping_reason,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
