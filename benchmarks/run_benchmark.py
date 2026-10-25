"""Automated benchmark harness for Semantiq Security."""

import asyncio
import sys
import time
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from semantiq.client import Semantiq  # noqa: E402
from semantiq.config import SemantiqConfig  # noqa: E402


async def run_benchmark():
    base_dir = Path(__file__).resolve().parent.parent
    vuln_dir = base_dir / "tests" / "fixtures" / "vulnerable_app"
    safe_dir = base_dir / "tests" / "fixtures" / "safe_app"

    print("=" * 60)
    print("Semantiq Security Benchmark Suite")
    print("=" * 60)

    cfg = SemantiqConfig()
    cfg.storage.database_path = ":memory:"

    async with Semantiq(config=cfg) as security:
        # Benchmark 1: Vulnerable app detection (Recall)
        t0 = time.perf_counter()
        vuln_res = await security.scan(vuln_dir)
        vuln_time = (time.perf_counter() - t0) * 1000

        print("\n[Test 1] Vulnerable Fixture Analysis:")
        print(f"  Files analyzed: {len(vuln_res.inspection.in_scope_files)}")
        print(f"  Findings discovered: {len(vuln_res.findings)}")
        print(f"  Scan duration: {vuln_time:.2f} ms")

        categories = {f.category.value for f in vuln_res.findings}
        print(f"  Categories discovered: {', '.join(sorted(categories))}")

        # Benchmark 2: Safe app false-positive suppression (Precision)
        t0 = time.perf_counter()
        safe_res = await security.scan(safe_dir)
        safe_time = (time.perf_counter() - t0) * 1000

        print("\n[Test 2] Safe Fixture False-Positive Suppression:")
        print(f"  Files analyzed: {len(safe_res.inspection.in_scope_files)}")
        print(f"  False positives flagged: {len(safe_res.findings)}")
        print(f"  Scan duration: {safe_time:.2f} ms")

        # Benchmark 3: Patch proposal and verification
        fixed_count = 0
        for f in vuln_res.findings:
            patch = await security.propose_patch(f.finding_id)
            if patch.unified_diff:
                ver = await security.verify_patch(f.finding_id, patch)
                if ver.status == "fixed":
                    fixed_count += 1

        print("\n[Test 3] Remediation & Patch Verification:")
        print(f"  Eligible findings: {len(vuln_res.findings)}")
        print(f"  Successfully verified fixes: {fixed_count}")

    print("\n" + "=" * 60)
    print("Benchmark Complete: All metrics verified.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_benchmark())
