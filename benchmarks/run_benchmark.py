"""Automated benchmark harness for Semantiq Security.

Evaluates precision, recall, false-positive suppression, and remediation
against explicitly labeled fixture ground truth manifests.
"""

import asyncio
import sys
import time
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from semantiq.client import Semantiq  # noqa: E402
from semantiq.config import SemantiqConfig  # noqa: E402
from semantiq.models import VulnerabilityCategory  # noqa: E402

# Labeled Ground Truth for Vulnerable Fixture
EXPECTED_CATEGORIES = {
    VulnerabilityCategory.COMMAND_INJECTION,
    VulnerabilityCategory.CODE_INJECTION,
    VulnerabilityCategory.SQL_INJECTION,
    VulnerabilityCategory.PATH_TRAVERSAL,
    VulnerabilityCategory.SSRF,
    VulnerabilityCategory.UNSAFE_DESERIALIZATION,
    VulnerabilityCategory.INSECURE_CRYPTO,
    VulnerabilityCategory.INSECURE_FILE_OPS,
    VulnerabilityCategory.HARDCODED_SECRET,
    VulnerabilityCategory.CROSS_SITE_SCRIPTING,
    VulnerabilityCategory.TEMPLATE_INJECTION,
    VulnerabilityCategory.INSECURE_REDIRECT,
    VulnerabilityCategory.BROKEN_OBJECT_LEVEL_AUTH,
    VulnerabilityCategory.AUTHORIZATION_BYPASS,
}


async def run_benchmark():
    base_dir = Path(__file__).resolve().parent.parent
    vuln_dir = base_dir / "tests" / "fixtures" / "vulnerable_app"
    safe_dir = base_dir / "tests" / "fixtures" / "safe_app"

    print("=" * 65)
    print("Semantiq Security Benchmark Suite (v0.1.0)")
    print("=" * 65)
    print("Methodology: Labeled fixture benchmark evaluating discovery precision,")
    print("recall, false-positive suppression, and patch verification against")
    print("ground-truth test suites.")
    print("Caveat: Fixture results measure algorithmic detector precision, but do not")
    print("generalize to broad production accuracy across arbitrary third-party code.")
    print("-" * 65)

    cfg = SemantiqConfig()
    cfg.storage.database_path = ":memory:"

    async with Semantiq(config=cfg) as security:
        # Benchmark 1: Vulnerable app detection (Recall & Category Coverage)
        t0 = time.perf_counter()
        vuln_res = await security.scan(vuln_dir)
        vuln_time = (time.perf_counter() - t0) * 1000

        discovered_categories = {f.category for f in vuln_res.findings}
        tp = len(vuln_res.findings)
        fn = len(EXPECTED_CATEGORIES - discovered_categories)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        print("\n[Benchmark 1] Vulnerable Repository Analysis (Recall):")
        print(f"  Files scanned: {len(vuln_res.inspection.in_scope_files)}")
        if vuln_res.coverage:
            print(f"  Coverage: {vuln_res.coverage.coverage_percentage:.1f}% ({vuln_res.coverage.parsed_files}/{vuln_res.coverage.in_scope_files} parsed)")
            print(f"  Unresolved call sites: {vuln_res.coverage.unresolved_calls_count}")
        print(f"  Total findings: {tp}")
        print(f"  Scan duration: {vuln_time:.2f} ms")
        print(f"  Categories discovered: {len(discovered_categories)} / {len(EXPECTED_CATEGORIES)}")
        for cat in sorted(c.value for c in discovered_categories):
            count = sum(1 for f in vuln_res.findings if f.category.value == cat)
            print(f"    - {cat:<24} : {count} occurrences")
        print(f"  Category Recall: {recall * 100:.1f}%")

        # Benchmark 2: Safe app false-positive suppression (Precision)
        t0 = time.perf_counter()
        safe_res = await security.scan(safe_dir)
        safe_time = (time.perf_counter() - t0) * 1000

        fp = len(safe_res.findings)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0

        print("\n[Benchmark 2] Safe Repository Analysis (Precision & Suppression):")
        print(f"  Files scanned: {len(safe_res.inspection.in_scope_files)}")
        print(f"  False positives flagged: {fp}")
        print(f"  Scan duration: {safe_time:.2f} ms")
        print(f"  Precision: {precision * 100:.1f}%")
        print(f"  False-positive rate: {(fp / len(safe_res.inspection.in_scope_files)) if safe_res.inspection.in_scope_files else 0:.2f}")

        # Benchmark 3: Patch proposal and verification
        fixed_count = 0
        candidate_count = 0
        for f in vuln_res.findings:
            if f.category in {VulnerabilityCategory.SQL_INJECTION, VulnerabilityCategory.HARDCODED_SECRET}:
                candidate_count += 1
                patch = await security.propose_patch(f.finding_id)
                if patch.unified_diff:
                    ver = await security.verify_patch(f.finding_id, patch)
                    if ver.status == "fixed":
                        fixed_count += 1

        print("\n[Benchmark 3] Remediation & Patch Verification:")
        print(f"  Candidate patchable findings: {candidate_count}")
        print(f"  Successfully verified fixes: {fixed_count}")
        fix_rate = (fixed_count / candidate_count * 100) if candidate_count > 0 else 0.0
        print(f"  Automated Fix Rate: {fix_rate:.1f}%")

        # Summary Metrics Table
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        print("\n" + "=" * 65)
        print("BENCHMARK SUMMARY METRICS:")
        print(f"  True Positives (TP):     {tp}")
        print(f"  False Positives (FP):    {fp}")
        print(f"  False Negatives (FN):    {fn}")
        print(f"  Precision:               {precision * 100:.1f}%")
        print(f"  Category Recall:         {recall * 100:.1f}%")
        print(f"  F1 Score:                {f1:.3f}")
        print("=" * 65)


if __name__ == "__main__":
    asyncio.run(run_benchmark())
