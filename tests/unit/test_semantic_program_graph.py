"""Unit tests for the Semantic Program Graph (SPG), language frontends, and data-flow analysis."""

from __future__ import annotations

from pathlib import Path

from semantiq.analysis.spg_dataflow import SPGDataFlowAnalyzer
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, GraphEdge, GraphNode, NodeKind, RelationshipProvenance
from semantiq.languages.javascript import JavaScriptFrontend
from semantiq.languages.python import PythonFrontend
from semantiq.storage.sqlite import SQLiteStorage


def test_spg_node_and_edge_creation() -> None:
    graph = SemanticProgramGraph()
    n1 = GraphNode(
        id="sym:app.py:main",
        kind=NodeKind.FUNCTION,
        label="main",
        file_path="app.py",
        start_line=1,
        end_line=5,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    n2 = GraphNode(
        id="sym:app.py:helper",
        kind=NodeKind.FUNCTION,
        label="helper",
        file_path="app.py",
        start_line=7,
        end_line=10,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_edge(
        GraphEdge(
            source_id=n1.id,
            target_id=n2.id,
            kind=EdgeKind.CALLS,
            provenance=RelationshipProvenance.DIRECT_FACT,
        )
    )

    assert graph.get_node(n1.id) is not None
    assert graph.get_callers(n2.id) == [n1]
    assert graph.get_callees(n1.id) == [n2]
    assert len(graph.find_paths(n1.id, n2.id)) == 1


def test_spg_python_frontend_on_fixture() -> None:
    repo_root = Path("tests/fixtures/multitenant_saas_app").resolve()
    frontend = PythonFrontend()
    graph = SemanticProgramGraph(repository_root=str(repo_root))

    app_path = "app.py"
    code = (repo_root / app_path).read_text(encoding="utf-8")
    res = frontend.parse_file(app_path, code, graph, repo_root)

    assert res.parsed_successfully is True
    assert res.nodes_created > 0
    assert res.edges_created > 0

    routes = graph.find_nodes(kind=NodeKind.ROUTE)
    assert len(routes) >= 5
    route_paths = [r.properties.get("route_path") for r in routes]
    assert "/api/v1/tenant/documents/<doc_id>" in route_paths


def test_spg_javascript_frontend_on_fixture() -> None:
    repo_root = Path("tests/fixtures/vulnerable_app").resolve()
    frontend = JavaScriptFrontend()
    graph = SemanticProgramGraph(repository_root=str(repo_root))

    js_path = "routes.js"
    code = (repo_root / js_path).read_text(encoding="utf-8")
    res = frontend.parse_file(js_path, code, graph, repo_root)

    assert res.parsed_successfully is True
    assert res.nodes_created > 0

    # Verify extracted JS routes and queries
    routes = graph.find_nodes(kind=NodeKind.ROUTE, file_path="routes.js")
    assert len(routes) >= 2
    queries = graph.find_nodes(kind=NodeKind.QUERY, file_path="routes.js")
    assert len(queries) >= 1


def test_spg_builder_cross_module_resolution() -> None:
    repo_root = Path("tests/fixtures/multitenant_saas_app").resolve()
    files = [
        "app.py",
        "dao/db.py",
        "services/tenant_service.py",
        "services/user_service.py",
        "services/role_service.py",
        "services/file_service.py",
        "services/webhook_service.py",
        "services/payment_service.py",
    ]

    builder = GraphBuilder(repo_root)
    build_res = builder.build(files)
    graph = build_res.graph

    assert build_res.files_indexed == 8
    assert len(graph.nodes) > 20

    # Test route reachability to queries
    chains = graph.find_route_to_sink_paths()
    assert len(chains) >= 1
    # Check that tenant document view reaches database execution
    doc_chains = [c for c in chains if "documents" in c["route_path"]]
    assert len(doc_chains) >= 1
    assert doc_chains[0]["hop_count"] >= 1


def test_spg_dataflow_analyzer_tracing() -> None:
    repo_root = Path("tests/fixtures/multitenant_saas_app").resolve()
    files = [
        "app.py",
        "dao/db.py",
        "services/tenant_service.py",
        "services/file_service.py",
        "services/webhook_service.py",
    ]
    builder = GraphBuilder(repo_root)
    build_res = builder.build(files)

    analyzer = SPGDataFlowAnalyzer(build_res.graph)
    traces = analyzer.trace_all_source_to_sinks()

    assert len(traces) >= 1
    # Check trace properties
    categories = {t.category for t in traces}
    assert any(c.value in ("sql_injection", "ssrf", "insecure_direct_file_access") for c in categories)


def test_spg_sqlite_persistence() -> None:
    storage = SQLiteStorage(":memory:")
    graph = SemanticProgramGraph(repository_root="test_repo", source_revision="rev_123")

    node = GraphNode(
        id="sym:test.py:exec",
        kind=NodeKind.FUNCTION,
        label="exec",
        file_path="test.py",
        start_line=1,
        end_line=5,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    graph.add_node(node)
    graph.add_edge(
        GraphEdge(
            source_id="repo:test_repo",
            target_id=node.id,
            kind=EdgeKind.DEFINES,
            provenance=RelationshipProvenance.DIRECT_FACT,
        )
    )

    storage.save_graph("test_repo", "rev_123", graph)
    loaded = storage.load_graph("test_repo", "rev_123")

    assert loaded is not None
    assert loaded.get_node(node.id) is not None
    assert len(loaded.nodes) == 1
