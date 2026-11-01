"""Comprehensive tests for Python semantic navigation, interprocedural analysis, and framework adapters."""

from __future__ import annotations

from pathlib import Path

import pytest

from semantiq.analysis.python_semantic import PythonSemanticEngine
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.models import EdgeKind, NodeKind, RelationshipProvenance
from semantiq.validation.contract_finalizer import ScanContractFinalizer


@pytest.fixture
def multi_module_repo(tmp_path: Path) -> Path:
    """Construct a multi-module repository with inheritance, overrides, aliases, and decorators."""
    # 1. Base auth service
    auth_dir = tmp_path / "services" / "auth"
    auth_dir.mkdir(parents=True)
    (auth_dir / "__init__.py").write_text(
        "from .base_auth import BaseAuthenticator\nfrom .token_auth import TokenAuthenticator\n__all__ = ['BaseAuthenticator', 'TokenAuthenticator']\n",
        encoding="utf-8",
    )
    (auth_dir / "base_auth.py").write_text(
        '''class BaseAuthenticator:
    def __init__(self, realm: str = "default") -> None:
        self.realm = realm

    def authenticate(self, token: str) -> bool:
        """Base authentication check."""
        return len(token) > 0

    def get_role(self, user_id: str) -> str:
        return "user"
''',
        encoding="utf-8",
    )
    (auth_dir / "token_auth.py").write_text(
        '''from .base_auth import BaseAuthenticator

class TokenAuthenticator(BaseAuthenticator):
    def authenticate(self, token: str) -> bool:
        """Overridden method in subclass."""
        if token.startswith("admin_"):
            return True
        return super().authenticate(token)

    def get_role(self, user_id: str) -> str:
        if user_id == "admin":
            return "administrator"
        return "user"
''',
        encoding="utf-8",
    )

    # 2. Database DAO with SQL sink and safe/unsafe methods
    dao_dir = tmp_path / "dao"
    dao_dir.mkdir(parents=True)
    (dao_dir / "__init__.py").write_text("", encoding="utf-8")
    (dao_dir / "user_dao.py").write_text(
        '''import sqlite3

class UserDAO:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(db_path)

    def find_user_unsafe(self, username: str) -> dict:
        query = f"SELECT * FROM users WHERE name = '{username}'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        return {"result": cursor.fetchone()}

    def find_user_safe(self, username: str) -> dict:
        query = "SELECT * FROM users WHERE name = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (username,))
        return {"result": cursor.fetchone()}
''',
        encoding="utf-8",
    )

    # 3. Web controllers using Bottle, Flask, and Tornado
    web_dir = tmp_path / "web"
    web_dir.mkdir(parents=True)
    (web_dir / "__init__.py").write_text("", encoding="utf-8")

    # Bottle controller
    (web_dir / "bottle_api.py").write_text(
        '''import bottle
from services.auth import TokenAuthenticator
from dao.user_dao import UserDAO

auth = TokenAuthenticator()
dao = UserDAO()

@bottle.route("/api/user/lookup", method="GET")
def lookup_user():
    username = bottle.request.GET.get("username")
    return dao.find_user_unsafe(username)

@bottle.route("/api/admin/raw_cmd", method="POST")
def execute_cmd():
    import os
    cmd = bottle.request.forms.get("cmd")
    return os.system(cmd)
''',
        encoding="utf-8",
    )

    # Flask controller
    (web_dir / "flask_api.py").write_text(
        '''from flask import Blueprint, request
from dao.user_dao import UserDAO

bp = Blueprint("flask_api", __name__)
dao = UserDAO()

def login_required(fn):
    return fn

@bp.route("/api/v1/profile", methods=["GET"])
@login_required
def get_profile():
    user = request.args.get("u")
    return dao.find_user_safe(user)

@bp.route("/api/v1/debug_exec", methods=["POST"])
def debug_exec():
    import subprocess
    cmd = request.form.get("command")
    return subprocess.run(cmd, shell=True)
''',
        encoding="utf-8",
    )

    # Tornado controller
    (web_dir / "tornado_api.py").write_text(
        '''import tornado.web
import os

class FileDownloadHandler(tornado.web.RequestHandler):
    def get(self):
        filename = self.get_argument("file")
        with open(filename, "r") as f:
            self.write(f.read())

class AuthenticatedSettingsHandler(tornado.web.RequestHandler):
    @tornado.web.authenticated
    def post(self):
        setting = self.get_body_argument("setting")
        self.write(f"Updated {setting}")
''',
        encoding="utf-8",
    )

    return tmp_path


def test_import_resolution_and_relative_navigation(multi_module_repo: Path) -> None:
    """Verify multi-module import resolution, relative imports, aliases, and __all__ re-exports."""
    engine = PythonSemanticEngine(multi_module_repo)
    for p in multi_module_repo.rglob("*.py"):
        rel = str(p.relative_to(multi_module_repo)).replace("\\", "/")
        engine.parse_source(rel, p.read_text(encoding="utf-8"))

    engine.link_project()

    # Verify services.auth package exports
    auth_pkg = engine.modules.get("services.auth")
    assert auth_pkg is not None
    assert "BaseAuthenticator" in auth_pkg.all_exports
    assert "TokenAuthenticator" in auth_pkg.all_exports

    # Verify class definitions
    base_auth_cls = engine.modules["services.auth.base_auth"].classes.get("BaseAuthenticator")
    assert base_auth_cls is not None
    assert "authenticate" in base_auth_cls.methods
    assert "get_role" in base_auth_cls.methods

    # Verify TokenAuthenticator inheritance and method override
    token_auth_cls = engine.modules["services.auth.token_auth"].classes.get("TokenAuthenticator")
    assert token_auth_cls is not None
    assert "BaseAuthenticator" in token_auth_cls.base_class_names
    assert "services.auth.base_auth.BaseAuthenticator" in token_auth_cls.resolved_bases
    assert token_auth_cls.mro == [
        "services.auth.token_auth.TokenAuthenticator",
        "services.auth.base_auth.BaseAuthenticator",
    ]


def test_class_inheritance_and_mro_overrides(multi_module_repo: Path) -> None:
    """Verify MRO computation and method overrides across module boundaries."""
    files = [
        "services/auth/__init__.py",
        "services/auth/base_auth.py",
        "services/auth/token_auth.py",
    ]
    builder = GraphBuilder(multi_module_repo)
    build_res = builder.build(files)
    graph = build_res.graph

    # Verify INHERITS edge
    subclass_nodes = graph.find_nodes(kind=NodeKind.CLASS, label="TokenAuthenticator")
    assert len(subclass_nodes) == 1
    sub_node = subclass_nodes[0]

    inherits_edges = [
        e for e in graph.out_edges.get(sub_node.id, [])
        if e.kind == EdgeKind.INHERITS
    ]
    assert len(inherits_edges) == 1
    target_cls = graph.get_node(inherits_edges[0].target_id)
    assert target_cls is not None
    assert target_cls.label == "BaseAuthenticator"

    # Verify OVERRIDES edge on authenticate method
    override_edges = []
    for edge_list in graph.out_edges.values():
        for e in edge_list:
            if e.kind == EdgeKind.OVERRIDES:
                override_edges.append(e)

    assert len(override_edges) >= 1
    override_src = graph.get_node(override_edges[0].source_id)
    override_tgt = graph.get_node(override_edges[0].target_id)
    assert override_src is not None and override_tgt is not None
    assert "authenticate" in override_src.label
    assert "authenticate" in override_tgt.label


def test_argument_mapping_positional_and_keyword(multi_module_repo: Path) -> None:
    """Verify callsite argument mapping (positional & keyword) and return value propagation."""
    files = [
        "dao/user_dao.py",
        "web/bottle_api.py",
    ]
    builder = GraphBuilder(multi_module_repo)
    build_res = builder.build(files)
    graph = build_res.graph

    # Trace argument from lookup_user into find_user_unsafe
    trace = graph.trace_argument_to_callee("lookup_user", "find_user_unsafe", 0)
    assert trace["status"] == "resolved"
    assert trace["call_site"] is not None
    assert "username" in trace["call_expression"]

    mapping = trace["selected_mapping"]
    assert mapping is not None
    assert mapping["arg_index"] == 0
    assert mapping["param_name"] == "username"
    assert mapping["arg_expression"] == "username"

    # Verify internal parameter propagation reached query sink
    prop = trace["parameter_propagation"]
    assert len(prop) >= 1
    assert any(p["target_kind"] == "query" for p in prop)


def test_framework_adapter_bottle_detection(multi_module_repo: Path) -> None:
    """Verify Bottle route detection, HTTP methods, request parameters, and sinks."""
    files = ["dao/user_dao.py", "web/bottle_api.py"]
    builder = GraphBuilder(multi_module_repo)
    build_res = builder.build(files)
    graph = build_res.graph

    bottle_routes = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/bottle_api.py")
    assert len(bottle_routes) == 2

    route_paths = {r.properties.get("route_path") for r in bottle_routes}
    assert "/api/user/lookup" in route_paths
    assert "/api/admin/raw_cmd" in route_paths

    # Check request inputs
    cmd_route = next(r for r in bottle_routes if r.properties.get("route_path") == "/api/admin/raw_cmd")
    inputs = cmd_route.properties.get("input_bindings", [])
    assert len(inputs) >= 1
    assert any(i["param_name"] in {"cmd", "forms"} for i in inputs)


def test_framework_adapter_flask_detection(multi_module_repo: Path) -> None:
    """Verify Flask Blueprint routes, @login_required guards, and subprocess exec sinks."""
    files = ["dao/user_dao.py", "web/flask_api.py"]
    builder = GraphBuilder(multi_module_repo)
    build_res = builder.build(files)
    graph = build_res.graph

    flask_routes = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/flask_api.py")
    assert len(flask_routes) == 2

    # Verify auth guard detection on /api/v1/profile
    profile_route = next(r for r in flask_routes if r.properties.get("route_path") == "/api/v1/profile")
    guards = graph.identify_route_guards(profile_route.id)
    assert guards["is_authenticated"] is True
    assert len(guards["enforced_guards"]) >= 1

    # Verify unguarded route /api/v1/debug_exec reaching subprocess sink
    debug_route = next(r for r in flask_routes if r.properties.get("route_path") == "/api/v1/debug_exec")
    debug_guards = graph.identify_route_guards(debug_route.id)
    assert debug_guards["is_authenticated"] is False
    assert len(debug_guards["bypassed_guards"]) >= 1


def test_framework_adapter_tornado_detection(multi_module_repo: Path) -> None:
    """Verify Tornado RequestHandler subclassing, get_argument inputs, and authenticated guards."""
    files = ["web/tornado_api.py"]
    builder = GraphBuilder(multi_module_repo)
    build_res = builder.build(files)
    graph = build_res.graph

    tornado_routes = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/tornado_api.py")
    assert len(tornado_routes) >= 2

    # Verify input detection on file download
    dl_route = next(r for r in tornado_routes if "filedownload" in r.id.lower() or "file" in r.label.lower())
    inputs = dl_route.properties.get("input_bindings", [])
    assert len(inputs) >= 1
    assert any(i["param_name"] in {"file", "argument"} for i in inputs)


def test_unresolved_dynamic_dispatch_reporting(tmp_path: Path) -> None:
    """Verify dynamic dispatch (getattr/setattr) is reported with explicit uncertainty."""
    dyn_file = tmp_path / "dynamic_handler.py"
    dyn_file.write_text(
        '''def dispatch_action(action_name: str, payload: dict):
    handler = getattr(__import__("handlers"), action_name)
    return handler(payload)
''',
        encoding="utf-8",
    )
    builder = GraphBuilder(tmp_path)
    build_res = builder.build(["dynamic_handler.py"])
    graph = build_res.graph

    unresolved = graph.get_unresolved_dispatches()
    assert len(unresolved) >= 1
    assert any("getattr" in str(u.get("dynamic_reason", "")) for u in unresolved)
    assert all(u.get("provenance") == RelationshipProvenance.UNRESOLVED.value for u in unresolved)
    assert all(u.get("confidence", 1.0) < 0.5 for u in unresolved)


def test_interprocedural_evidence_chain_and_phase1_contract(multi_module_repo: Path) -> None:
    """Verify get_interprocedural_evidence_path produces valid CodeEvidence that finalizes cleanly."""
    files = [
        "dao/user_dao.py",
        "web/bottle_api.py",
    ]
    builder = GraphBuilder(multi_module_repo)
    build_res = builder.build(files)
    graph = build_res.graph

    path_res = graph.get_interprocedural_evidence_path(
        source_entry="/api/user/lookup",
        sink_id_or_expr="find_user_unsafe",
    )
    assert path_res["status"] == "path_resolved"
    evidence_chain = path_res["evidence_chain"]
    assert len(evidence_chain) >= 5

    # Check semantic roles present
    roles = [e["role"] for e in evidence_chain]
    assert "user_input" in roles
    assert "entrypoint" in roles
    assert "propagation" in roles
    assert "sink" in roles
    assert "outcome" in roles

    # Verify compatibility with Phase 1 ScanContractFinalizer
    from semantiq.models import (
        CodeEvidence,
        CodeEvidenceRole,
        ConfidenceLevel,
        Finding,
        FindingLifecycleState,
        SeverityLevel,
    )

    finding = Finding(
        finding_id="F-TEST-001",
        occurrence_id="occ_test_001",
        confidence=ConfidenceLevel.HIGH,
        rule_id="AI-DISCOVERY-SQL-INJECTION",
        title="Unauthenticated SQL Injection in User Lookup",
        category="sql_injection",
        severity=SeverityLevel.HIGH,
        file_path="web/bottle_api.py",
        start_line=11,
        end_line=13,
        summary="Untrusted input from bottle.request.GET propagates directly into SQL query sink without sanitization.",
        code_evidence=[
            CodeEvidence(
                evidence_id=f"ev_{idx:03d}",
                file_path=item["file_path"],
                start_line=item["start_line"],
                end_line=item["end_line"],
                role=CodeEvidenceRole(item["role"]),
                explanation=item["explanation"],
                snippet=item["snippet"],
            )
            for idx, item in enumerate(evidence_chain, start=1)
        ],
        root_cause_evidence_refs=[f"ev_{idx:03d}" for idx in range(1, len(evidence_chain) + 1)],
        lifecycle_state=FindingLifecycleState.CONFIRMED,
    )

    finalizer = ScanContractFinalizer(multi_module_repo)
    report = finalizer.finalize([finding], scan_id="test_contract_phase2")
    assert report.total_findings_evaluated == 1
    assert report.valid_findings_count == 1
    assert report.error_count == 0
    assert report.sarif_output is not None
    assert len(report.sarif_output) > 0
