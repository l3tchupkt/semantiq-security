"""Integrating Semantiq into an autonomous security agent harness."""

import asyncio

from semantiq import Semantiq


async def run_security_triage_loop(target_repo: str):
    async with Semantiq() as security:
        print(f"[*] Triaging {target_repo}...")

        # 1. Inspect repository
        inspection = await security.inspect_repository(target_repo)
        print(f"[*] Analyzed {len(inspection.in_scope_files)} files.")

        # 2. Build threat model
        threat_model = await security.build_threat_model(target_repo)
        print(f"[*] Identified {len(threat_model.entry_points)} entry points.")

        # 3. Perform scan
        scan_result = await security.scan(target_repo)
        print(f"[+] Total findings: {len(scan_result.findings)}")

        # 4. Patch high-priority findings
        for finding in scan_result.findings:
            if finding.severity in ("critical", "high"):
                print(f"[!] Processing critical issue: {finding.title}")
                patch = await security.propose_patch(finding.finding_id)
                if patch.unified_diff:
                    print(f"[+] Proposed patch invariant: {patch.invariant_enforced}")
                    verification = await security.verify_patch(finding.finding_id, patch)
                    print(f"[+] Patch verification outcome: {verification.status}")


if __name__ == "__main__":
    asyncio.run(run_security_triage_loop("."))
