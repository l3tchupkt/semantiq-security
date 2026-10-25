"""Multi-stage vulnerability discovery pipeline."""

from __future__ import annotations

from pathlib import Path

from semantiq.analysis.context import ContextCollector
from semantiq.analysis.interprocedural import build_repository_symbol_table
from semantiq.analysis.python_ast import analyze_python_source
from semantiq.analysis.regex_patterns import analyze_javascript_source
from semantiq.config import ScanConfig
from semantiq.discovery.secrets import analyze_secrets
from semantiq.events import EventBus, EventType, ScanEvent
from semantiq.models import Finding, SeverityLevel, ValidationStatus
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.repository.safepath import resolve_safe_path

SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 0,
    SeverityLevel.HIGH: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 3,
    SeverityLevel.INFORMATIONAL: 4,
}


def _matches_focus(finding: Finding, focus_categories: list[str]) -> bool:
    """Check if finding category matches the requested focus list."""
    if not focus_categories:
        return True
    cat_normalized = finding.category.value.lower().replace("_", "-")
    focus_normalized = [f.lower().replace("_", "-") for f in focus_categories]
    return cat_normalized in focus_normalized or finding.category.value in focus_categories


class VulnerabilityDiscoveryEngine:
    """Orchestrates deterministic multi-stage vulnerability discovery and verification."""

    def __init__(
        self,
        repository_root: Path,
        config: ScanConfig | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self.repository_root = repository_root
        self.config = config or ScanConfig()
        self.event_bus = event_bus or EventBus()
        self.context_collector = ContextCollector(repository_root)
        self.intelligence = RepositoryIntelligence(repository_root)

    def scan_files(
        self,
        files: list[str],
        scan_id: str = "scan_local",
    ) -> list[Finding]:
        """Execute deterministic multi-stage discovery over in-scope files."""
        # Stage A & B: Repository Intelligence & Symbol Table Indexing
        self.intelligence.index_repository(files)

        python_files = [f for f in files if f.endswith((".py", ".pyi"))]
        symbol_table = build_repository_symbol_table(self.repository_root, python_files)

        # Stage C & D: Deterministic Detection & Cross-Module Analysis
        raw_candidates: list[Finding] = []

        for rel_file in files:
            try:
                full_path = resolve_safe_path(self.repository_root, rel_file)
            except Exception:
                continue

            if not full_path.exists() or not full_path.is_file():
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            self.event_bus.emit(
                ScanEvent(
                    event_type=EventType.FILE_ANALYSIS_STARTED,
                    scan_id=scan_id,
                    message=f"Analyzing {rel_file}",
                    payload={"file": rel_file},
                )
            )

            # Analyze Python source with cross-file symbol table
            if rel_file.endswith((".py", ".pyi")):
                py_findings = analyze_python_source(rel_file, content, symbol_table=symbol_table)
                raw_candidates.extend(py_findings)

            # Analyze JS/TS source
            elif rel_file.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
                js_findings = analyze_javascript_source(rel_file, content)
                raw_candidates.extend(js_findings)

            # Analyze secrets across all code and configs
            secret_findings = analyze_secrets(rel_file, content)
            raw_candidates.extend(secret_findings)

            self.event_bus.emit(
                ScanEvent(
                    event_type=EventType.FILE_ANALYZED,
                    scan_id=scan_id,
                    message=f"Completed {rel_file}",
                    payload={"file": rel_file},
                )
            )

        # Stage F: Evidence Verification & Context Enrichment
        verified_candidates: list[Finding] = []
        for finding in raw_candidates:
            finding.scan_id = scan_id

            # Verify file presence and line bounds
            target_path = self.repository_root / finding.file_path
            if not target_path.exists():
                finding.validation_status = ValidationStatus.REJECTED
                continue

            surrounding, start_l, end_l = self.context_collector.get_surrounding_code(
                finding.file_path,
                finding.start_line,
                finding.end_line,
                context_lines=4,
            )
            if surrounding and finding.code_evidence:
                finding.code_evidence[0].snippet = surrounding

            verified_candidates.append(finding)

        # Stage H: Deduplication by fingerprint
        unique_findings: dict[str, Finding] = {}
        for candidate in verified_candidates:
            # Filter by focus if configured
            if not _matches_focus(candidate, self.config.focus):
                continue

            fp = candidate.fingerprint or candidate.calculate_fingerprint()
            if fp not in unique_findings:
                unique_findings[fp] = candidate
            else:
                # Merge locations
                existing = unique_findings[fp]
                for loc in candidate.locations:
                    if loc not in existing.locations:
                        existing.locations.append(loc)

        # Prioritization by severity
        consolidated = list(unique_findings.values())
        consolidated.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        for finding in consolidated:
            self.event_bus.emit(
                ScanEvent(
                    event_type=EventType.FINDING_DISCOVERED,
                    scan_id=scan_id,
                    message=f"Discovered {finding.title} in {finding.file_path}:{finding.start_line}",
                    payload={"finding_id": finding.finding_id, "title": finding.title},
                )
            )

        return consolidated
