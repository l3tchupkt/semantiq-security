"""Unit tests for context-sensitive sanitization, parameter-to-return propagation, and control-flow joins."""

from semantiq.analysis.interprocedural import RepositorySymbolTable, index_source_file
from semantiq.analysis.python_ast import analyze_python_source
from semantiq.analysis.rules import GLOBAL_RULE_REGISTRY
from semantiq.models import VulnerabilityCategory


def test_sanitizer_context_sensitivity_shlex_quote() -> None:
    # shlex.quote is safe for COMMAND_INJECTION, but NOT for SQL_INJECTION
    sql_with_shlex = """
import shlex

def search_user(cursor):
    raw_input = request.args.get("name")
    escaped_for_shell = shlex.quote(raw_input)
    # VULNERABLE: shlex.quote does not sanitize SQL!
    cursor.execute(f"SELECT * FROM users WHERE name = '{escaped_for_shell}'")
"""
    findings = analyze_python_source("query.py", sql_with_shlex)
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.SQL_INJECTION
    assert findings[0].rule_id == "SQ-PY-002"

    cmd_with_shlex = """
import shlex
import subprocess

def run_backup():
    dest = request.args.get("dest")
    quoted_dest = shlex.quote(dest)
    # SAFE: shlex.quote properly sanitizes shell command string
    subprocess.run(f"tar -czf backup.tar.gz {quoted_dest}", shell=True)
"""
    cmd_findings = analyze_python_source("backup.py", cmd_with_shlex)
    assert len(cmd_findings) == 0


def test_sanitizer_context_sensitivity_html_escape() -> None:
    # html.escape is safe for XSS, but NOT for Command Injection
    cmd_with_html_escape = """
import html
import os

def ping_host():
    host = request.args.get("h")
    escaped_html = html.escape(host)
    # VULNERABLE: html.escape does not neutralize shell injection!
    os.system(f"ping -c 1 {escaped_html}")
"""
    findings = analyze_python_source("network.py", cmd_with_html_escape)
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.COMMAND_INJECTION
    assert findings[0].rule_id == "SQ-PY-001"

    xss_with_html_escape = """
import html

def greeting_view():
    user = request.args.get("u")
    safe_user = html.escape(user)
    # SAFE: html.escape properly prevents XSS in HTML response
    return make_response(f"<h1>Welcome {safe_user}</h1>")
"""
    xss_findings = analyze_python_source("view.py", xss_with_html_escape)
    assert len(xss_findings) == 0


def test_parameter_to_return_taint_propagation() -> None:
    # Taint propagates from helper parameter to return value, then into caller sink
    helper_code = """
def build_query(value):
    return f"SELECT * FROM users WHERE name = '{value}'"
"""
    app_code = """
from db import build_query

def search(request, cursor):
    user_input = request.args.get("name")
    query = build_query(user_input)
    cursor.execute(query)
"""
    sym_table = RepositorySymbolTable()
    for s in index_source_file("db.py", helper_code):
        sym_table.add_summary(s)

    findings = analyze_python_source("app.py", app_code, symbol_table=sym_table)
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.SQL_INJECTION
    assert any("Return value of" in step.description for step in findings[0].data_flow)


def test_container_taint_propagation() -> None:
    code = """
def process_data(cursor):
    raw_val = request.args.get("q")
    items = [raw_val, "fixed"]
    query = f"SELECT * FROM inventory WHERE code = '{items[0]}'"
    cursor.execute(query)
"""
    findings = analyze_python_source("inv.py", code)
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.SQL_INJECTION


def test_try_except_may_taint_join() -> None:
    code = """
def handle_payment(cursor):
    try:
        user_code = request.args.get("promo")
    except ValueError:
        user_code = "fallback"
    cursor.execute(f"SELECT * FROM promos WHERE code = '{user_code}'")
"""
    findings = analyze_python_source("pay.py", code)
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.SQL_INJECTION


def test_rule_registry_metadata() -> None:
    rule = GLOBAL_RULE_REGISTRY.get_rule("SQ-PY-002")
    assert rule is not None
    assert rule.category == VulnerabilityCategory.SQL_INJECTION
    assert "CWE-89" in rule.cwe_ids
    assert "int" in rule.valid_sanitizers
    assert "shlex.quote" not in rule.valid_sanitizers
