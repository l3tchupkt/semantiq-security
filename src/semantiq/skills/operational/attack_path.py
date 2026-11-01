"""Attack Path Analysis Skill (SQ-SKILL-ATTACK-PATH).

Connects untrusted entry points to dangerous operations across multi-hop calls,
constructs structured causal attack chains, and calibrates severity based on reachability.
"""

from __future__ import annotations

from semantiq.analysis.spg_dataflow import SPGDataFlowAnalyzer
from semantiq.graph.builder import GraphBuilder
from semantiq.models import CodeEvidence, CodeEvidenceRole, Finding, SeverityLevel
from semantiq.skills.contract import (
    SecuritySkillContract,
    SkillBudget,
    SkillCategory,
    SkillInputContext,
    SkillOutput,
    SkillPermission,
)
from semantiq.skills.operational.base import BaseSecuritySkill
from semantiq.skills.sandbox import SkillSandbox


class AttackPathAnalysisSkill(BaseSecuritySkill):
    """Operational skill performing interprocedural attack-path tracing."""

    def __init__(self) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.attack_path_analysis",
            name="Attack Path Analysis & Reachability Calibration",
            description="Traces multi-hop interprocedural dataflows from entry points to sinks and calibrates severity.",
            category=SkillCategory.ANALYSIS,
            required_permissions=[SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
            required_inputs=["repository_root", "candidate_findings"],
            optional_inputs=["target_files"],
            dependencies=["sq.skill.finding_discovery"],
            budget=SkillBudget(max_turns=10, timeout_seconds=60.0, max_tokens=25000),
            success_criteria="Causal attack paths attached with entrypoint, propagation, and sink evidence.",
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Trace attack paths for candidate findings."""
        sandbox.verify_graph_access()

        # Build Semantic Program Graph across target files
        files = list(context.target_files)
        if not files:
            files = list({f.file_path for f in context.candidate_findings if f.file_path})

        builder = GraphBuilder(repo_root=context.repository_root)
        graph_res = builder.build(files)
        graph = graph_res.graph
        analyzer = SPGDataFlowAnalyzer(graph)

        analyzed_findings: list[Finding] = []
        for cand in context.candidate_findings:
            # Check for existing entrypoint in code_evidence
            roles = {e.role for e in cand.code_evidence}
            has_entrypoint = CodeEvidenceRole.ENTRYPOINT in roles
            has_sink = CodeEvidenceRole.SINK in roles

            # If sink or entrypoint evidence is incomplete, trace dataflow paths
            if not has_entrypoint or not has_sink:
                traces = analyzer.trace_all_source_to_sinks()
                matching_traces = [
                    t
                    for t in traces
                    if t.sink_node.file_path == cand.file_path or t.category == cand.category
                ]

                updated_evidence = list(cand.code_evidence)
                if matching_traces:
                    trace = matching_traces[0]
                    # Add entrypoint evidence
                    if not has_entrypoint:
                        updated_evidence.insert(
                            0,
                            CodeEvidence(
                                file_path=trace.source_node.file_path,
                                start_line=trace.source_node.start_line,
                                end_line=trace.source_node.end_line or trace.source_node.start_line,
                                role=CodeEvidenceRole.ENTRYPOINT,
                                explanation=f"External entry point reaching {cand.category.value}",
                                snippet=f"# Entry point in {trace.source_node.file_path}:{trace.source_node.start_line}",
                            ),
                        )
                    # Add sink evidence
                    if not has_sink:
                        updated_evidence.append(
                            CodeEvidence(
                                file_path=trace.sink_node.file_path,
                                start_line=trace.sink_node.start_line,
                                end_line=trace.sink_node.end_line or trace.sink_node.start_line,
                                role=CodeEvidenceRole.SINK,
                                explanation=f"Sensitive operation sink: {trace.sink_node.label}",
                                snippet=f"# Sink in {trace.sink_node.file_path}:{trace.sink_node.start_line}",
                            ),
                        )

                # Calibrate severity: If complete entrypoint-to-sink path is proven, elevate or confirm severity
                calibrated_sev = cand.severity
                if (
                    CodeEvidenceRole.ENTRYPOINT in {e.role for e in updated_evidence}
                    and cand.severity == SeverityLevel.LOW
                ):
                    calibrated_sev = SeverityLevel.MEDIUM

                cand_dict = cand.model_dump()
                cand_dict["code_evidence"] = [e.model_dump() for e in updated_evidence]
                cand_dict["severity"] = calibrated_sev
                analyzed_findings.append(Finding.model_validate(cand_dict))
            else:
                analyzed_findings.append(cand)

        return SkillOutput(
            skill_id=self.contract.skill_id,
            success=True,
            findings=analyzed_findings,
            artifacts={
                "paths_analyzed": len(analyzed_findings),
                "graph_nodes": len(graph.nodes),
            },
            stopping_reason="completed",
        )
