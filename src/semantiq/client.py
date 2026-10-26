"""Main client facade for Semantiq Security SDK."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from semantiq.analysis.spg_dataflow import SPGDataFlowAnalyzer
from semantiq.config import SemantiqConfig
from semantiq.discovery.engine import VulnerabilityDiscoveryEngine
from semantiq.events import EventBus, EventHandler, EventType, ScanEvent
from semantiq.exceptions import TargetNotFoundError
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import NodeKind
from semantiq.models import (
    Finding,
    InvestigationHypothesis,
    PatchProposal,
    PatchVerificationResult,
    RepositoryInspection,
    ScanResult,
    ThreatModel,
    ValidationMode,
    ValidationResult,
)
from semantiq.providers import get_ai_provider
from semantiq.remediation.generator import propose_patch
from semantiq.remediation.verifier import verify_patch
from semantiq.reporting.exporter import export_json, export_markdown, export_sarif
from semantiq.repository.git import get_diff_changed_files
from semantiq.repository.inspector import RepositoryInspector
from semantiq.storage.sqlite import SQLiteStorage
from semantiq.threat_model.generator import ThreatModelExtractor
from semantiq.validation.engine import ValidationEngine


class Semantiq:
    """Primary asynchronous client for Semantiq Security."""

    def __init__(
        self,
        config: SemantiqConfig | None = None,
        config_path: str | Path | None = None,
    ) -> None:
        if config:
            self.config = config
        elif config_path:
            self.config = SemantiqConfig.load_from_file(config_path)
        else:
            self.config = SemantiqConfig.from_env()

        self.event_bus = EventBus()
        self.storage = SQLiteStorage(self.config.storage.database_path)
        self.ai_provider = get_ai_provider(self.config.ai) if self.config.ai.enabled else None

    async def __aenter__(self) -> Semantiq:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Release any client resources."""
        pass

    def on_event(self, handler: EventHandler) -> None:
        """Subscribe an event handler callback to scan progress events."""
        self.event_bus.subscribe(handler)

    async def inspect_repository(self, path: str | Path) -> RepositoryInspection:
        """Inspect repository, detect languages, Git metadata, and compile inventory."""
        target = Path(path).expanduser().resolve()
        inspector = RepositoryInspector(self.config.scan)
        return inspector.inspect(target)

    async def build_threat_model(self, path: str | Path) -> ThreatModel:
        """Construct codebase threat model with entry points and trust boundaries."""
        target = Path(path).expanduser().resolve()
        inspection = await self.inspect_repository(target)
        extractor = ThreatModelExtractor(target)
        threat_model = extractor.build_threat_model(inspection.in_scope_files)

        if self.ai_provider and self.config.ai.enabled:
            threat_model = await self.ai_provider.enrich_threat_model(
                threat_model,
                summary_context=f"Scanned {len(inspection.in_scope_files)} files in {target.name}",
            )
        return threat_model

    async def scan(
        self,
        target: str | Path,
        focus: list[str] | None = None,
        mode: str = "standard",
        scope_paths: list[str] | None = None,
    ) -> ScanResult:
        """Execute comprehensive security analysis over target codebase."""
        repo_path = Path(target).expanduser().resolve()
        if not repo_path.exists() or not repo_path.is_dir():
            raise TargetNotFoundError(f"Target repository path not found: {target}")

        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc).isoformat()

        self.event_bus.emit(
            ScanEvent(
                event_type=EventType.SCAN_STARTED,
                scan_id=scan_id,
                message=f"Starting Semantiq security scan on {repo_path.name}",
                payload={"target": str(repo_path), "mode": mode},
            )
        )

        scan_cfg = self.config.scan.model_copy()
        if focus is not None:
            scan_cfg.focus = focus
        if scope_paths:
            scan_cfg.scope_paths = scope_paths

        # Stage 1: Inventory
        inspector = RepositoryInspector(scan_cfg)
        inspection = inspector.inspect(repo_path)

        self.event_bus.emit(
            ScanEvent(
                event_type=EventType.INSPECTION_COMPLETED,
                scan_id=scan_id,
                message=f"Inventoried {len(inspection.in_scope_files)} in-scope files",
                payload={"in_scope_count": len(inspection.in_scope_files)},
            )
        )

        # Stage 2: Threat Modeling
        threat_extractor = ThreatModelExtractor(repo_path)
        threat_model = threat_extractor.build_threat_model(inspection.in_scope_files)

        self.event_bus.emit(
            ScanEvent(
                event_type=EventType.THREAT_MODEL_BUILT,
                scan_id=scan_id,
                message=f"Identified {len(threat_model.entry_points)} entry points and {len(threat_model.trust_boundaries)} trust boundaries",
                payload={"entry_points": len(threat_model.entry_points)},
            )
        )

        # Stage 3: Vulnerability Discovery & Deep Investigation
        engine = VulnerabilityDiscoveryEngine(
            repo_path,
            config=scan_cfg,
            ai_provider=self.ai_provider,
            event_bus=self.event_bus,
        )
        findings = engine.scan_files(inspection.in_scope_files, scan_id=scan_id)
        coverage_report = engine.get_coverage(inspection.in_scope_files)

        # Update inspection with coverage and architectural facts
        inspection.coverage = coverage_report
        inspection.unresolved_calls = list(engine.intelligence.unresolved_calls)
        inspection.auth_boundaries = list(engine.intelligence.auth_boundaries)

        # Stage 4: Default Static Validation for findings
        val_engine = ValidationEngine(repo_path, config=self.config.validation)
        for f in findings:
            val_res = val_engine.validate_finding(f, mode=ValidationMode.STATIC)
            f.validation_status = val_res.status
            f.validation_result = val_res

        completed_at = datetime.now(timezone.utc).isoformat()

        coverage_summary = {
            "total_files": inspection.total_files,
            "in_scope_files_count": len(inspection.in_scope_files),
            "excluded_files_count": len(inspection.excluded_files),
            "findings_count": len(findings),
            "threat_model_entry_points": len(threat_model.entry_points),
            "coverage_percentage": coverage_report.coverage_percentage,
            "unresolved_calls_count": coverage_report.unresolved_calls_count,
        }

        result = ScanResult(
            scan_id=scan_id,
            target_path=str(repo_path),
            git_revision=inspection.git_revision,
            mode=mode,
            findings=findings,
            threat_model=threat_model,
            inspection=inspection,
            started_at=started_at,
            completed_at=completed_at,
            coverage_summary=coverage_summary,
            coverage=coverage_report,
        )

        # Save to storage
        self.storage.save_scan(result)

        self.event_bus.emit(
            ScanEvent(
                event_type=EventType.SCAN_COMPLETED,
                scan_id=scan_id,
                message=f"Scan complete with {len(findings)} findings",
                payload={"findings_count": len(findings)},
            )
        )

        return result

    async def scan_diff(
        self,
        target: str | Path,
        base: str,
        head: str | None = None,
    ) -> ScanResult:
        """Perform security analysis focused on Git diff between two revisions."""
        repo_path = Path(target).expanduser().resolve()
        changed_files = get_diff_changed_files(repo_path, base, head)
        if not changed_files:
            # Fallback to inspecting working tree if diff is empty
            inspection = await self.inspect_repository(repo_path)
            changed_files = inspection.in_scope_files

        scan_id = f"scan_diff_{uuid.uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc).isoformat()

        inspector = RepositoryInspector(self.config.scan)
        inspection = inspector.inspect(repo_path)
        # Filter in-scope files strictly to changed files
        filtered_files = [f for f in inspection.in_scope_files if f in changed_files]

        threat_extractor = ThreatModelExtractor(repo_path)
        threat_model = threat_extractor.build_threat_model(filtered_files)

        engine = VulnerabilityDiscoveryEngine(repo_path, config=self.config.scan, event_bus=self.event_bus)
        findings = engine.scan_files(filtered_files, scan_id=scan_id)

        val_engine = ValidationEngine(repo_path, config=self.config.validation)
        for f in findings:
            val_res = val_engine.validate_finding(f, mode=ValidationMode.STATIC)
            f.validation_status = val_res.status
            f.validation_result = val_res

        completed_at = datetime.now(timezone.utc).isoformat()
        result = ScanResult(
            scan_id=scan_id,
            target_path=str(repo_path),
            git_revision=f"{base}..{head or 'HEAD'}",
            mode="diff",
            findings=findings,
            threat_model=threat_model,
            inspection=inspection,
            started_at=started_at,
            completed_at=completed_at,
            coverage_summary={"diff_files_analyzed": len(filtered_files)},
        )

        self.storage.save_scan(result)
        return result

    async def get_findings(self, scan_id: str) -> list[Finding]:
        """Retrieve stored findings for a scan."""
        return self.storage.get_findings_by_scan(scan_id)

    async def investigate(self, finding_id: str) -> dict[str, Any]:
        """Perform deeper investigation into a finding."""
        finding = self.storage.get_finding_by_id(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        if self.ai_provider and self.config.ai.enabled:
            snippet = finding.code_evidence[0].snippet if finding.code_evidence else ""
            return await self.ai_provider.investigate_finding(finding, snippet)
        else:
            return {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "cwe_ids": finding.cwe_ids,
                "location": f"{finding.file_path}:{finding.start_line}",
                "analysis_mode": "deterministic_offline",
                "remediation": finding.remediation,
            }

    def _get_target_path_for_finding(self, finding: Finding) -> Path:
        if finding.scan_id:
            for s in self.storage.list_scans():
                if s["scan_id"] == finding.scan_id:
                    return Path(s["target_path"]).resolve()
        return Path(".").resolve()

    async def validate(
        self,
        finding_id: str,
        mode: ValidationMode = ValidationMode.STATIC,
        test_command: list[str] | None = None,
    ) -> ValidationResult:
        """Validate a finding under a specified verification mode."""
        finding = self.storage.get_finding_by_id(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        repo_path = self._get_target_path_for_finding(finding)
        val_engine = ValidationEngine(repo_path, config=self.config.validation)
        return val_engine.validate_finding(finding, mode=mode, test_command=test_command)

    async def propose_patch(self, finding_id: str) -> PatchProposal:
        """Generate a unified diff patch for a finding."""
        finding = self.storage.get_finding_by_id(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        repo_path = self._get_target_path_for_finding(finding)
        return propose_patch(finding, repo_path)

    async def verify_patch(
        self,
        finding_id: str,
        patch: PatchProposal | None = None,
    ) -> PatchVerificationResult:
        """Verify patch against regression checks in isolated copy."""
        finding = self.storage.get_finding_by_id(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        repo_path = self._get_target_path_for_finding(finding)
        p = patch or propose_patch(finding, repo_path)
        return verify_patch(repo_path, p)

    async def export_report(self, scan_id: str, format: str = "json") -> str:
        """Export report for a completed scan in json, markdown, or sarif."""
        scans = self.storage.list_scans()
        scan_meta = next((s for s in scans if s["scan_id"] == scan_id), None)
        if not scan_meta:
            raise ValueError(f"Scan ID {scan_id} not found in database.")

        findings = self.storage.get_findings_by_scan(scan_id)
        scan_result = ScanResult(
            scan_id=scan_id,
            target_path=scan_meta["target_path"],
            git_revision=scan_meta["git_revision"],
            mode=scan_meta["mode"],
            findings=findings,
            inspection=RepositoryInspection(
                root_path=scan_meta["target_path"],
                is_git=bool(scan_meta["git_revision"]),
                git_revision=scan_meta["git_revision"],
            ),
            started_at=scan_meta["started_at"],
            completed_at=scan_meta["completed_at"],
        )

        fmt = format.lower().strip()
        if fmt == "json":
            return export_json(scan_result)
        elif fmt == "markdown" or fmt == "md":
            return export_markdown(scan_result)
        elif fmt == "sarif":
            return export_sarif(scan_result)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    # Phase 2 & 7: Semantic Program Graph (SPG) and Memory Primitives
    async def get_semantic_graph(self, target: str | Path) -> SemanticProgramGraph:
        """Retrieve or build the Semantic Program Graph for a repository."""
        repo_path = Path(target).expanduser().resolve()
        insp = await self.inspect_repository(repo_path)
        rev = insp.git_revision or ""
        cached = self.storage.load_graph(str(repo_path), rev)
        if cached:
            return cached

        builder = GraphBuilder(repo_path, source_revision=rev)
        result = builder.build(insp.in_scope_files)
        self.storage.save_graph(str(repo_path), rev, result.graph)
        return result.graph

    async def query_symbols(
        self,
        target: str | Path,
        query: str | None = None,
        kind: str | None = None,
        file_path: str | None = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """Query symbols in the Semantic Program Graph."""
        graph = await self.get_semantic_graph(target)
        k_enum = NodeKind(kind) if kind else None
        nodes = graph.find_nodes(kind=k_enum, file_path=file_path)

        if query:
            q_lower = query.lower()
            nodes = [n for n in nodes if q_lower in n.label.lower() or q_lower in n.id.lower()]

        results = []
        for n in nodes[:limit]:
            results.append({
                "id": n.id,
                "kind": n.kind.value,
                "label": n.label,
                "file_path": n.file_path,
                "start_line": n.start_line,
                "end_line": n.end_line,
                "provenance": n.provenance.value,
                "properties": n.properties,
            })
        return results

    async def query_callers_callees(
        self,
        target: str | Path,
        symbol_name: str,
        direction: str = "both",
    ) -> dict[str, Any]:
        """Lookup callers and callees for a target symbol."""
        graph = await self.get_semantic_graph(target)
        matching = [n for n in graph.nodes.values() if n.label == symbol_name or n.label.endswith(f".{symbol_name}")]
        if not matching:
            return {"error": f"Symbol '{symbol_name}' not found in semantic graph", "callers": [], "callees": []}

        symbol_node = matching[0]
        callers = [c.model_dump() for c in graph.get_callers(symbol_node.id)] if direction in ("callers", "both") else []
        callees = [c.model_dump() for c in graph.get_callees(symbol_node.id)] if direction in ("callees", "both") else []

        return {
            "symbol": symbol_node.model_dump(),
            "callers": callers,
            "callees": callees,
        }

    async def query_neighborhood(
        self,
        target: str | Path,
        node_id: str,
        radius: int = 1,
    ) -> dict[str, Any]:
        """Extract a bounded subgraph around a node for agent reasoning."""
        graph = await self.get_semantic_graph(target)
        clamped_radius = max(1, min(3, radius))
        return graph.get_neighborhood(node_id, radius=clamped_radius)

    async def query_dataflow_paths(
        self,
        target: str | Path,
        source_symbol: str | None = None,
        sink_category: str | None = None,
        max_depth: int = 10,
    ) -> list[dict[str, Any]]:
        """Trace cross-file dataflow paths from route parameters to sensitive sinks."""
        graph = await self.get_semantic_graph(target)
        analyzer = SPGDataFlowAnalyzer(graph, max_depth=max_depth)
        traces = analyzer.trace_all_source_to_sinks()

        results = []
        for t in traces:
            if source_symbol and source_symbol.lower() not in t.source_node.label.lower():
                continue
            if sink_category and sink_category.lower() not in t.category.value.lower():
                continue

            results.append({
                "source": t.source_node.model_dump(),
                "sink": t.sink_node.model_dump(),
                "category": t.category.value,
                "is_sanitized": t.is_sanitized,
                "sanitizer": t.sanitizer_name,
                "is_authorized": t.is_authorized,
                "is_tenant_scoped": t.is_tenant_scoped,
                "confidence": t.confidence,
                "steps": [s.model_dump() for s in t.steps],
                "path_length": len(t.path_nodes),
            })
        return results

    async def query_route_reachability(
        self,
        target: str | Path,
        route_path: str | None = None,
        sink_kind: str | None = None,
    ) -> list[dict[str, Any]]:
        """Identify reachability chains from HTTP routes to sensitive operations."""
        graph = await self.get_semantic_graph(target)
        k_enum = NodeKind(sink_kind) if sink_kind else None
        return graph.find_route_to_sink_paths(route_id=route_path, sink_kind=k_enum)

    async def query_authorization_path(
        self,
        target: str | Path,
        route_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Inspect route authentication decorators, authorization checks, and sensitive queries."""
        graph = await self.get_semantic_graph(target)
        routes = graph.find_nodes(kind=NodeKind.ROUTE)
        if route_path:
            routes = [r for r in routes if route_path in r.properties.get("route_path", r.label)]

        results = []
        for r in routes:
            boundary_info = graph.find_boundary_crossings(r.id)
            results.append(boundary_info)
        return results

    async def query_tenant_isolation(
        self,
        target: str | Path,
        with_ownership_check: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Inspect resource access paths with and without tenant ownership enforcement."""
        graph = await self.get_semantic_graph(target)
        return graph.find_resource_access_paths(with_ownership_check=with_ownership_check)

    async def get_analysis_gaps(self, target: str | Path) -> dict[str, Any]:
        """Report unresolved dynamic calls, unparsed files, and unsupported syntax."""
        repo_path = Path(target).expanduser().resolve()
        insp = await self.inspect_repository(repo_path)
        graph = await self.get_semantic_graph(repo_path)
        unresolved_regions = graph.find_unresolved_regions()

        gap_notes = list(insp.coverage.gap_notes) if insp.coverage else []
        failed_files = list(insp.coverage.failed_parsing_files) if insp.coverage else []

        return {
            "unresolved_dynamic_calls": unresolved_regions,
            "failed_parsing_files": failed_files,
            "gap_notes": gap_notes,
            "total_unresolved": len(unresolved_regions),
        }

    async def record_hypothesis(
        self,
        target: str | Path,
        statement: str,
        target_symbol: str,
        entry_point: str,
        rule_id: str,
        disposition: str = "open",
    ) -> dict[str, Any]:
        """Record structured security hypothesis in persistent memory."""
        repo_path = Path(target).expanduser().resolve()
        hyp_id = f"hyp_{uuid.uuid4().hex[:8]}"
        hypothesis = InvestigationHypothesis(
            hypothesis_id=hyp_id,
            rule_id=rule_id,
            target_symbol=target_symbol,
            entry_point=entry_point,
            sensitive_operation="",
            statement=statement,
            disposition=disposition,
        )
        self.storage.save_hypothesis(hypothesis, scan_id="manual_investigation", repo_path=str(repo_path))
        return hypothesis.model_dump()

    async def get_evidence(self, finding_id: str) -> dict[str, Any]:
        """Retrieve verifiable evidence, snippets, citations, and dataflow steps for a finding."""
        finding = self.storage.get_finding_by_id(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        return {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "file_path": finding.file_path,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "code_evidence": [e.model_dump() for e in finding.code_evidence],
            "data_flow": [s.model_dump() for s in finding.data_flow],
            "supporting_evidence": finding.supporting_evidence,
            "counterevidence": finding.counterevidence,
            "hypothesis": finding.hypothesis.model_dump() if finding.hypothesis else None,
            "uncertainty": finding.uncertainty,
            "validation_status": finding.validation_status.value,
        }
