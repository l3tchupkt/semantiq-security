"""Phase 7 Deep Scan Orchestration Benchmark & Comparative Evaluation.

Evaluates DeepScanCoordinator across three orchestration modes:
- SEQUENTIAL
- PARALLEL (concurrency = 4)
- ADAPTIVE

Across targets:
1. NASA-AMMOS/AIT-GUI (Bottle Web App)
2. pyload/pyload (Flask Web App & Plugins)
3. gitpython-developers/GitPython (Git Library & CLI Wrapper)

Validates:
- Elimination of Phase 6 pyload performance bottleneck.
- Dynamic investigation packet planning.
- Fault tolerance, worker isolation, and retry handling.
- Evidence-preserving reduction.
- Durable SQLite Workbench Schema v6 persistence.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from evals.autonomous_discovery.dataset_registry import (
    DATASET_REGISTRY,
    GroundTruthVulnerability,
)
from evals.autonomous_discovery.run_autonomous_discovery_evaluation import get_scoped_py_files
from semantiq.integrations.sarif import SARIFExporter
from semantiq.models import CodeEvidenceRole, Finding, FindingLifecycleState
from semantiq.orchestration.deep_coordinator import DeepScanCoordinator, OrchestrationMode
from semantiq.storage.sqlite import SQLiteStorage

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("evals.phase7.deep_orchestration")

EVAL_DIR = Path(__file__).resolve().parent
DB_PATH = EVAL_DIR / "workbench_phase7.db"
METRICS_PATH = EVAL_DIR / "phase7_metrics.json"
SARIF_PATH = EVAL_DIR / "phase7_findings.sarif"

# Historical Phase 6 baselines for speedup factor calculation
PHASE6_BASELINES = {
    "nasa_ait_gui": 8.1,
    "pyload": 1924.1,
    "gitpython": 17.4,
}


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


async def run_evaluation() -> None:
    """Execute complete comparative evaluation across Sequential, Parallel, and Adaptive modes."""
    logger.info("=== Starting Phase 7 Deep Scan Orchestration Benchmark ===")
    t_benchmark_start = time.perf_counter()

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
        "modes_evaluated": ["sequential", "parallel", "adaptive"],
        "targets": {},
        "comparative_summary": {},
    }

    modes_to_test = [
        OrchestrationMode.SEQUENTIAL,
        OrchestrationMode.PARALLEL,
        OrchestrationMode.ADAPTIVE,
    ]

    for target_key, spec in DATASET_REGISTRY.items():
        logger.info("==================================================")
        logger.info("Evaluating Target: %s (%s)", spec.name, spec.pinned_commit)
        logger.info("==================================================")
        if not spec.root_path.exists():
            logger.error("Target path %s does not exist. Skipping.", spec.root_path)
            continue

        scoped_files = get_scoped_py_files(spec.root_path, spec.in_scope_subpaths)
        logger.info("Scoped files for %s: %d", spec.name, len(scoped_files))

        target_mode_results: dict[str, Any] = {}

        for mode in modes_to_test:
            scan_id = f"p7_{mode.value}_{spec.repo_id}"
            coordinator = DeepScanCoordinator(
                repository_root=spec.root_path,
                storage=storage,
                source_revision=spec.pinned_commit,
            )

            t0 = time.perf_counter()
            findings, worker_records, reducer_res = await coordinator.run_deep_scan(
                target_files=scoped_files,
                mode=mode,
                max_workers=4,
                scan_id=scan_id,
            )
            elapsed = round(time.perf_counter() - t0, 2)

            metrics = evaluate_findings_against_ground_truth(findings, spec.ground_truth)
            metrics["elapsed_seconds"] = elapsed

            # Speedup factor compared to Phase 6
            p6_base = PHASE6_BASELINES.get(target_key, elapsed)
            speedup = round(p6_base / max(0.1, elapsed), 2)
            metrics["phase6_baseline_seconds"] = p6_base
            metrics["speedup_factor"] = speedup

            completed_packets = sum(
                1 for w in worker_records if w.status.value in ("completed", "partially_completed")
            )
            metrics["orchestration_telemetry"] = {
                "mode": mode.value,
                "workers_executed": len(worker_records),
                "packets_completed": completed_packets,
                "packets_failed": sum(1 for w in worker_records if w.status.value == "failed"),
                "total_tokens": sum(w.tokens_used for w in worker_records),
            }
            metrics["reducer_summary"] = {
                "total_raw": reducer_res.total_raw_findings,
                "accepted": reducer_res.accepted_count,
                "merged": reducer_res.merged_count,
                "contradicted": reducer_res.contradicted_count,
            }

            logger.info(
                "[%s | %s] Elapsed: %.2fs (Speedup: %.2fx) | Active Findings: %d (Merged: %d) | TP: %d, FP: %d",
                spec.name,
                mode.value.upper(),
                elapsed,
                speedup,
                metrics["total_active_findings"],
                metrics["reducer_summary"]["merged"],
                metrics["true_positives"],
                metrics["false_positives"],
            )

            target_mode_results[mode.value] = metrics

            # Accumulate representative findings for SARIF export (from parallel mode)
            if mode == OrchestrationMode.PARALLEL:
                for f in findings:
                    if f.lifecycle_state != FindingLifecycleState.REJECTED:
                        all_confirmed_findings.append(f)

        benchmark_results["targets"][target_key] = {
            "name": spec.name,
            "commit": spec.pinned_commit,
            "architecture": spec.architecture_style,
            "files_evaluated": len(scoped_files),
            "modes": target_mode_results,
        }

    # Comparative aggregate summary
    benchmark_results["comparative_summary"] = {
        "pyload_speedup_parallel": benchmark_results["targets"]
        .get("pyload", {})
        .get("modes", {})
        .get("parallel", {})
        .get("speedup_factor", 1.0),
        "pyload_speedup_sequential": benchmark_results["targets"]
        .get("pyload", {})
        .get("modes", {})
        .get("sequential", {})
        .get("speedup_factor", 1.0),
        "ait_gui_parallel_seconds": benchmark_results["targets"]
        .get("nasa_ait_gui", {})
        .get("modes", {})
        .get("parallel", {})
        .get("elapsed_seconds", 0.0),
        "gitpython_parallel_seconds": benchmark_results["targets"]
        .get("gitpython", {})
        .get("modes", {})
        .get("parallel", {})
        .get("elapsed_seconds", 0.0),
        "total_benchmark_time_seconds": round(time.perf_counter() - t_benchmark_start, 2),
    }

    METRICS_PATH.write_text(json.dumps(benchmark_results, indent=2), encoding="utf-8")
    logger.info("Saved Phase 7 metrics to %s", METRICS_PATH)

    sarif_doc = SARIFExporter.export(
        findings=all_confirmed_findings,
        tool_name="Semantiq Security Deep Scan Coordinator",
        tool_version="0.1.0",
        scan_id="scan_phase7_deep_benchmark",
    )
    SARIF_PATH.write_text(sarif_doc, encoding="utf-8")
    logger.info("Exported SARIF 2.1.0 document to %s", SARIF_PATH)

    total_time = round(time.perf_counter() - t_benchmark_start, 2)
    logger.info("=== Phase 7 Benchmark Complete in %.2fs ===", total_time)
    print("\n================== PHASE 7 BENCHMARK COMPLETE ==================")
    print(f"Total Benchmark Execution Time: {total_time:.2f}s")
    for _t_key, t_data in benchmark_results["targets"].items():
        modes = t_data.get("modes", {})
        seq_time = modes.get("sequential", {}).get("elapsed_seconds", 0.0)
        par_time = modes.get("parallel", {}).get("elapsed_seconds", 0.0)
        adp_time = modes.get("adaptive", {}).get("elapsed_seconds", 0.0)
        speedup = modes.get("parallel", {}).get("speedup_factor", 1.0)
        print(f"Target: {t_data['name']} ({t_data['files_evaluated']} files)")
        print(
            f"  Sequential: {seq_time:.2f}s | Parallel: {par_time:.2f}s | Adaptive: {adp_time:.2f}s | Speedup: {speedup}x"
        )


def main() -> None:
    asyncio.run(run_evaluation())


if __name__ == "__main__":
    main()
