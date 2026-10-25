"""Unit tests for Python AST vulnerability analyzer."""

from pathlib import Path

from semantiq.analysis.python_ast import analyze_python_source
from semantiq.models import VulnerabilityCategory


def test_analyze_python_vulnerabilities(vulnerable_app_dir: Path) -> None:
    code = (vulnerable_app_dir / "app.py").read_text(encoding="utf-8")
    findings = analyze_python_source("app.py", code)

    categories = {f.category for f in findings}
    rule_ids = {f.rule_id for f in findings}

    # Verify all expected categories are discovered
    assert VulnerabilityCategory.COMMAND_INJECTION in categories
    assert VulnerabilityCategory.SQL_INJECTION in categories
    assert VulnerabilityCategory.PATH_TRAVERSAL in categories
    assert VulnerabilityCategory.SSRF in categories
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in categories
    assert VulnerabilityCategory.INSECURE_CRYPTO in categories
    assert VulnerabilityCategory.INSECURE_FILE_OPS in categories

    # Verify rule IDs
    assert "SQ-PY-001" in rule_ids
    assert "SQ-PY-002" in rule_ids
    assert "SQ-PY-003" in rule_ids
    assert "SQ-PY-004" in rule_ids
    assert "SQ-PY-005" in rule_ids
    assert "SQ-PY-006" in rule_ids
    assert "SQ-PY-007" in rule_ids
    assert "SQ-PY-008" in rule_ids

    # Verify evidence and line coordinates
    for f in findings:
        assert f.start_line > 0
        assert f.end_line >= f.start_line
        assert f.code_evidence
        assert f.fingerprint.startswith("semantiq/v1:sha256:")


def test_analyze_python_safe_fixture(safe_app_dir: Path) -> None:
    code = (safe_app_dir / "app.py").read_text(encoding="utf-8")
    findings = analyze_python_source("app.py", code)
    # Safe fixture should trigger zero false positives
    assert len(findings) == 0


def test_intra_procedural_taint_dataflow() -> None:
    code = """
def handler():
    raw_id = request.args.get("user_id")
    query = f"SELECT * FROM accounts WHERE id = {raw_id}"
    cursor.execute(query)
"""
    findings = analyze_python_source("handler.py", code)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == VulnerabilityCategory.SQL_INJECTION
    assert len(f.data_flow) >= 2
    assert f.data_flow[0].location.role == "source"
    assert "Untrusted source" in f.data_flow[0].description
    assert f.data_flow[-1].location.role == "sink"


def test_constant_variable_assignment_no_false_positive() -> None:
    code = """
def get_user(user_id: int):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
"""
    findings = analyze_python_source("service.py", code)
    assert len(findings) == 0


def test_code_injection_eval_exec() -> None:
    code = """
def run_calc():
    expr = request.form.get("formula")
    return eval(expr)
"""
    findings = analyze_python_source("calc.py", code)
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.CODE_INJECTION
    assert findings[0].rule_id == "SQ-PY-009"


def test_ssti_detection() -> None:
    code = """
def render_greeting():
    name = request.args.get("name")
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)
"""
    findings = analyze_python_source("views.py", code)
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.CODE_INJECTION
    assert findings[0].rule_id == "SQ-PY-010"


def test_sanitizer_neutralizes_taint() -> None:
    code = """
import shlex
def execute_cmd():
    user_file = request.args.get("file")
    safe_arg = shlex.quote(user_file)
    subprocess.run(["cat", safe_arg])
"""
    findings = analyze_python_source("cmd.py", code)
    # Passed as array without shell=True, plus shlex.quote -> no command injection finding
    assert len(findings) == 0

