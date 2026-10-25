"""Unit tests for repository intelligence layer, symbol indexing, and call graph analysis."""

from pathlib import Path

from semantiq.models import SeverityLevel, VulnerabilityCategory
from semantiq.repository.intelligence import RepositoryIntelligence


def test_repository_intelligence_python_indexing(tmp_path: Path) -> None:
    code = """
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

class AccountService:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_account(self, account_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM accounts WHERE id = '{account_id}'")
        return cursor.fetchone()

@app.route("/api/account/<id>")
def account_view(id):
    svc = AccountService("data.db")
    return svc.get_account(id)
"""
    app_file = tmp_path / "app.py"
    app_file.write_text(code, encoding="utf-8")

    intel = RepositoryIntelligence(tmp_path)
    intel.index_repository(["app.py"])

    # 1. Verify file metadata and hashes
    assert "app.py" in intel.file_metadata
    meta = intel.file_metadata["app.py"]
    assert meta.language == "python"
    assert len(meta.sha256) == 64

    # 2. Verify framework detection
    assert "flask" in intel.frameworks_detected

    # 3. Verify symbol indexing
    symbols = intel.symbols.get("app.py", [])
    sym_names = [s.name for s in symbols]
    assert "AccountService" in sym_names
    assert "__init__" in sym_names
    assert "get_account" in sym_names
    assert "account_view" in sym_names

    # Verify route entry point detection
    route_sym = next(s for s in symbols if s.name == "account_view")
    assert route_sym.is_entry_point is True
    assert route_sym.framework == "flask"

    # 4. Verify imports indexing
    imports = intel.imports.get("app.py", [])
    import_mods = [i.imported_module for i in imports]
    assert "os" in import_mods
    assert "sqlite3" in import_mods
    assert "flask" in import_mods

    # 5. Verify security sinks
    sinks = intel.security_sinks
    assert any(s.category == VulnerabilityCategory.SQL_INJECTION for s in sinks)
    sql_sink = next(s for s in sinks if s.category == VulnerabilityCategory.SQL_INJECTION)
    assert sql_sink.severity == SeverityLevel.HIGH
    assert sql_sink.symbol_name == "get_account"

    # 6. Verify call graph
    call_names = [c.callee_name for c in intel.call_graph]
    assert "execute" in call_names
    assert "connect" in call_names
