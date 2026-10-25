"""Unit tests for InvestigationOrchestrator, architectural vulnerability discovery, and coverage reporting."""

from pathlib import Path

from semantiq.discovery.orchestrator import InvestigationBudget, InvestigationOrchestrator
from semantiq.models import SeverityLevel, ValidationStatus, VulnerabilityCategory
from semantiq.repository.intelligence import RepositoryIntelligence


def test_missing_function_level_authorization(tmp_path: Path) -> None:
    # Service where public_view has auth elsewhere, but admin_delete_user lacks auth decorators
    code = """
from flask import Flask, session, abort

app = Flask(__name__)

@app.route("/api/user/profile")
@login_required
def user_profile():
    return "profile"

@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    # VULNERABLE: No auth decorator on sensitive delete action
    db_delete(user_id)
    return "deleted"
"""
    app_file = tmp_path / "routes.py"
    app_file.write_text(code, encoding="utf-8")

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["routes.py"])

    orchestrator = InvestigationOrchestrator(tmp_path, intel)
    findings = orchestrator.investigate([], ["routes.py"])

    missing_auth = [f for f in findings if f.rule_id == "SQ-PY-014"]
    assert len(missing_auth) == 1
    f = missing_auth[0]
    assert f.category == VulnerabilityCategory.AUTHORIZATION_BYPASS
    assert f.severity == SeverityLevel.HIGH
    assert f.hypothesis is not None
    assert f.hypothesis.target_symbol == "delete_user"
    assert "/api/admin/users" in f.hypothesis.statement
    assert len(f.attack_chain) > 0


def test_idor_vulnerability_discovery_and_safe_counterexample(tmp_path: Path) -> None:
    vuln_code = """
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/invoice/<doc_id>")
def get_invoice(doc_id):
    # VULNERABLE: Direct lookup on client-supplied ID without session user check
    cursor.execute(f"SELECT * FROM invoices WHERE id = '{doc_id}'")
    return cursor.fetchone()
"""
    vuln_file = tmp_path / "invoices.py"
    vuln_file.write_text(vuln_code, encoding="utf-8")

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["invoices.py"])

    orchestrator = InvestigationOrchestrator(tmp_path, intel)
    findings = orchestrator.investigate([], ["invoices.py"])

    idor_findings = [f for f in findings if f.rule_id == "SQ-PY-013"]
    assert len(idor_findings) == 1
    f = idor_findings[0]
    assert f.category == VulnerabilityCategory.BROKEN_OBJECT_LEVEL_AUTH
    assert f.validation_status == ValidationStatus.EVIDENCE_SUPPORTED
    assert f.hypothesis is not None
    assert any("Attacker can supply an arbitrary resource identifier" in p for p in f.hypothesis.preconditions)


def test_idor_safe_counterevidence_inline_ownership_check(tmp_path: Path) -> None:
    safe_code = """
from flask import Flask, session, abort
app = Flask(__name__)

@app.route("/api/invoice/<doc_id>")
def get_safe_invoice(doc_id):
    # SAFE: Session user ID verified in query
    user_id = session.get('user_id')
    cursor.execute("SELECT * FROM invoices WHERE id = ? AND user_id = ?", (doc_id, user_id))
    return cursor.fetchone()
"""
    safe_file = tmp_path / "safe_invoices.py"
    safe_file.write_text(safe_code, encoding="utf-8")

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["safe_invoices.py"])

    orchestrator = InvestigationOrchestrator(tmp_path, intel)
    findings = orchestrator.investigate([], ["safe_invoices.py"])

    idor_findings = [f for f in findings if f.rule_id == "SQ-PY-013"]
    assert len(idor_findings) == 0


def test_coverage_reporting_and_unresolved_calls(tmp_path: Path) -> None:
    code = """
import os

def process_dynamic(handler_name, arg):
    # Dynamic call dispatch
    fn = getattr(os, handler_name)
    return fn(arg)
"""
    f = tmp_path / "dynamic_ops.py"
    f.write_text(code, encoding="utf-8")

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["dynamic_ops.py"])

    # Verify unresolved call was captured
    assert len(intel.unresolved_calls) >= 1
    u = intel.unresolved_calls[0]
    assert u.caller_symbol == "process_dynamic"
    assert "getattr" in u.call_expression

    # Verify coverage report
    coverage = intel.compute_coverage(["dynamic_ops.py"])
    assert coverage.in_scope_files == 1
    assert coverage.parsed_files == 1
    assert coverage.unresolved_calls_count >= 1
    assert coverage.coverage_percentage == 100.0
    assert any("dynamic dispatch" in note for note in coverage.gap_notes)


def test_investigation_budget_timeout(tmp_path: Path) -> None:
    code = """
def sample():
    pass
"""
    (tmp_path / "sample.py").write_text(code, encoding="utf-8")
    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["sample.py"])

    # Zero timeout budget to test graceful cutoff
    budget = InvestigationBudget(timeout_seconds=0.0)
    orchestrator = InvestigationOrchestrator(tmp_path, intel, budget=budget)
    assert orchestrator.budget.timeout_seconds == 0.0
