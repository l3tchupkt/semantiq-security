"""Unit tests for threat modeling engine."""

from pathlib import Path

from semantiq.threat_model.generator import ThreatModelExtractor


def test_build_threat_model(vulnerable_app_dir: Path) -> None:
    extractor = ThreatModelExtractor(vulnerable_app_dir)
    in_scope_files = ["app.py", "routes.js"]
    threat_model = extractor.build_threat_model(in_scope_files, app_name="TestApp")

    assert threat_model.application_name == "TestApp"
    assert len(threat_model.assets) >= 4
    assert len(threat_model.trust_boundaries) >= 3
    # Sinks found: subprocess, db execute, etc.
    assert len(threat_model.sensitive_operations) >= 2
    # Routes in JS: get, etc.
    assert any(ep.kind == "http_route" for ep in threat_model.entry_points)
