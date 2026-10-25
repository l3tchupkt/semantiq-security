"""Integration test for full end-to-end scanning workflow."""

import asyncio
from pathlib import Path

from semantiq.client import Semantiq
from semantiq.config import SemantiqConfig


def test_full_scan_workflow(vulnerable_app_dir: Path) -> None:
    async def _test() -> None:
        cfg = SemantiqConfig()
        cfg.storage.database_path = ":memory:"

        async with Semantiq(config=cfg) as security:
            # Run scan
            result = await security.scan(vulnerable_app_dir)

            assert result.scan_id.startswith("scan_")
            assert len(result.findings) >= 5
            assert result.threat_model is not None
            assert len(result.threat_model.entry_points) >= 1

            # Test finding retrieval from storage
            stored_findings = await security.get_findings(result.scan_id)
            assert len(stored_findings) == len(result.findings)

            # Test Markdown export
            md = await security.export_report(result.scan_id, format="markdown")
            assert "# Semantiq Security Scan Report" in md
            assert result.scan_id in md

            # Test SARIF export
            sarif = await security.export_report(result.scan_id, format="sarif")
            assert '"version": "2.1.0"' in sarif
            assert '"name": "Semantiq Security"' in sarif

    asyncio.run(_test())
