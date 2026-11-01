"""Phase 6 Skill-Driven Evaluation Harness.

Executes autonomous skill-driven investigations across the three benchmark repositories:
  1. NASA-AMMOS/AIT-GUI (b9df6fc551ad6788ffd16e2451492dce12ead9cc)
  2. pyload (1b12dc7f348db8c144e0f39215680415e90ca4d2)
  3. GitPython (3481da9618e69063464c94447167d83bd45505a9)

Outputs:
  - evals/phase6/skill_discovery_metrics.json
  - evals/phase6/workbench_phase6.db
  - evals/phase6/phase6_findings.sarif
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from evals.autonomous_discovery.dataset_registry import (
    DATASET_REGISTRY,
    GroundTruthVulnerability,
)
from evals.autonomous_discovery.run_autonomous_discovery_evaluation import get_scoped_py_files
from semantiq.discovery.coordinator import InvestigationCoordinator
from semantiq.integrations.sarif import SARIFExporter
from semantiq.models import CodeEvidenceRole, Finding, FindingLifecycleState
from semantiq.skills import SkillInputContext
from semantiq.storage.sqlite import SQLiteStorage

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("Phase6Evaluation")

OUTPUT_DIR = Path(__file__).resolve().parent
DB_PATH = OUTPUT_DIR / "workbench_phase6.db"
METRICS_PATH = OUTPUT_DIR / "skill_discovery_metrics.json"
SARIF_PATH = OUTPUT_DIR / "phase6_findings.sarif"


def evaluate_findings_against_ground_truth(
    findings: list[Finding],
    ground_truth: list[GroundTruthVulnerability],
) -> dict[str, Any]:
    """Calculate true positives, false positives, precision, recall, and completeness."""
    active_findings = [f for f in findings if f.lifecycle_state != FindingLifecycleState.REJECTED]
    vulnerable_gt = [gt for gt in ground_truth if not gt.is_mitigated]
    negative_controls = [gt for gt in ground_truth if gt.is_mitigated]

    matched_gt: set[str] = set()
    matched_findings: set[str] = set()
    matched_mitigated_gt: set[str] = set()

    for gt in ground_truth:
        for f in active_findings:
            f_file = f.file_path.replace("\\", "/")
            gt_file = gt.file_path.replace("\\", "/")

            file_match = f_file.endswith(gt_file) or gt_file.endswith(f_file)
            symbol_match = gt.target_symbol.lower() in (f.title or "").lower() or any(
                gt.target_symbol.lower() in (loc.symbol or "").lower() for loc in f.locations
            )
            cat_match = f.category == gt.category

            if file_match and (symbol_match or cat_match):
                if gt.is_mitigated:
                    matched_mitigated_gt.add(gt.vuln_id)
                else:
                    matched_gt.add(gt.vuln_id)
                    matched_findings.add(f.finding_id)
                break

    tp = len(matched_gt)
    fp = max(0, len(active_findings) - len(matched_findings))
    fn = len(vulnerable_gt) - tp

    precision = round((tp / (tp + fp)) * 100.0, 1) if (tp + fp) > 0 else 0.0
    recall = round((tp / len(vulnerable_gt)) * 100.0, 1) if vulnerable_gt else 0.0

    complete_count = 0
    for f in active_findings:
        roles = {getattr(e, "role", "") for e in f.code_evidence}
        if CodeEvidenceRole.ENTRYPOINT in roles and CodeEvidenceRole.SINK in roles:
            complete_count += 1
    completeness = round((complete_count / max(1, len(active_findings))) * 100.0, 1)

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "total_active_findings": len(active_findings),
        "precision": precision,
        "recall": recall,
        "exploit_path_completeness": completeness,
        "ground_truth_vulnerable_count": len(vulnerable_gt),
        "negative_controls_total": len(negative_controls),
        "negative_controls_rejected": len(negative_controls) - len(matched_mitigated_gt),
        "matched_ground_truth_ids": sorted(matched_gt),
        "matched_mitigated_negative_control_ids": sorted(matched_mitigated_gt),
    }


def main() -> None:
    """Execute Phase 6 skill-driven evaluation across all targets."""
    logger.info("=== Starting Phase 6 Skill Architecture Benchmark ===")
    t_start = time.perf_counter()

    if DB_PATH.exists():
        DB_PATH.unlink()
    storage = SQLiteStorage(str(DB_PATH))

    # Transparency check for live AI provider
    nvidia_key = os.environ.get("NVIDIA_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    has_live_provider = bool(nvidia_key or openai_key or anthropic_key)

    provider_status = (
        "LIVE_PROVIDER_ACTIVE"
        if has_live_provider
        else "NOT RUN (API key not present in environment; deterministic engine benchmark evaluated)"
    )
    logger.info("Provider Execution Status: %s", provider_status)

    all_confirmed_findings: list[Finding] = []
    benchmark_results: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider_execution_status": provider_status,
        "semantiq_version": "0.1.0",
        "targets": {},
        "aggregate_comparison": {},
    }

    tot_tp = 0
    tot_fp = 0
    tot_vulnerable_gt = 0
    tot_negative_controls = 0
    tot_negative_rejected = 0

    for target_key, spec in DATASET_REGISTRY.items():
        logger.info("--- Evaluating Target: %s (%s) ---", spec.name, spec.pinned_commit)
        if not spec.root_path.exists():
            logger.error("Target path %s does not exist. Skipping.", spec.root_path)
            continue

        scoped_files = get_scoped_py_files(spec.root_path, spec.in_scope_subpaths)
        logger.info("Found %d in-scope Python files for %s", len(scoped_files), spec.name)

        vulnerable_gt_count = len([gt for gt in spec.ground_truth if not gt.is_mitigated])
        negative_ctrl_count = len([gt for gt in spec.ground_truth if gt.is_mitigated])
        tot_vulnerable_gt += vulnerable_gt_count
        tot_negative_controls += negative_ctrl_count

        coord = InvestigationCoordinator(
            repository_root=spec.root_path,
            storage=storage,
            source_revision=spec.pinned_commit,
        )

        ctx = SkillInputContext(
            repository_root=spec.root_path,
            target_files=scoped_files,
        )

        t0 = time.perf_counter()
        findings, outputs, reducer_res = coord.coordinate_skill_investigation(
            context=ctx,
            scan_id=f"scan_p6_{spec.repo_id}",
        )
        elapsed = round(time.perf_counter() - t0, 2)

        metrics = evaluate_findings_against_ground_truth(findings, spec.ground_truth)
        metrics["elapsed_seconds"] = elapsed
        metrics["skills_executed"] = [
            {
                "skill_id": o.skill_id,
                "success": o.success,
                "latency_seconds": o.telemetry.get("latency_seconds", 0.0),
                "status": o.telemetry.get("status", ""),
            }
            for o in outputs
        ]
        metrics["reducer_summary"] = {
            "total_raw": reducer_res.total_raw_findings,
            "accepted": reducer_res.accepted_count,
            "merged": reducer_res.merged_count,
            "contradicted": reducer_res.contradicted_count,
        }

        tot_tp += metrics["true_positives"]
        tot_fp += metrics["false_positives"]
        tot_negative_rejected += metrics["negative_controls_rejected"]

        for f in findings:
            if f.lifecycle_state != FindingLifecycleState.REJECTED:
                all_confirmed_findings.append(f)

        benchmark_results["targets"][target_key] = {
            "name": spec.name,
            "commit": spec.pinned_commit,
            "architecture": spec.architecture_style,
            "files_evaluated": len(scoped_files),
            "metrics": metrics,
        }

    agg_prec = round((tot_tp / max(1, tot_tp + tot_fp)) * 100.0, 1)
    agg_rec = round((tot_tp / max(1, tot_vulnerable_gt)) * 100.0, 1)

    benchmark_results["aggregate_comparison"] = {
        "true_positives": tot_tp,
        "false_positives": tot_fp,
        "precision": agg_prec,
        "recall": agg_rec,
        "ground_truth_vulnerable_total": tot_vulnerable_gt,
        "negative_controls_total": tot_negative_controls,
        "negative_controls_rejected": tot_negative_rejected,
    }

    METRICS_PATH.write_text(json.dumps(benchmark_results, indent=2), encoding="utf-8")
    logger.info("Saved Phase 6 metrics to %s", METRICS_PATH)

    sarif_doc = SARIFExporter.export(
        findings=all_confirmed_findings,
        tool_name="Semantiq Security Skill System",
        tool_version="0.1.0",
        scan_id="scan_phase6_skill_benchmark",
    )
    SARIF_PATH.write_text(sarif_doc, encoding="utf-8")
    logger.info("Exported SARIF 2.1.0 document to %s", SARIF_PATH)

    total_time = round(time.perf_counter() - t_start, 2)
    logger.info("=== Phase 6 Benchmark Complete in %.2fs ===", total_time)
    print("\n================== PHASE 6 BENCHMARK SUMMARY ==================")
    print(
        f"Skill Architecture: TP={tot_tp}/{tot_vulnerable_gt} (Recall: {agg_rec}%), FP={tot_fp}, Precision: {agg_prec}%"
    )
    print(f"Negative Controls Rejected: {tot_negative_rejected}/{tot_negative_controls}")
    print("===============================================================\n")


if __name__ == "__main__":
    main()
