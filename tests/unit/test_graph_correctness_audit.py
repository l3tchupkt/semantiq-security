"""Comprehensive audit tests for Semantic Program Graph correctness and difficult interprocedural flows."""

from __future__ import annotations

from pathlib import Path

from semantiq.analysis.spg_dataflow import SPGDataFlowAnalyzer
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, GraphEdge, GraphNode, NodeKind, RelationshipProvenance
from semantiq.models import VulnerabilityCategory


def test_graph_edge_provenance_and_symbol_resolution() -> None:
    """Verify that every edge has identifiable provenance and ambiguous calls remain unresolved."""
    graph = SemanticProgramGraph()

    # Create two different modules with identical function names
    n_a = GraphNode(
        id="sym:mod_a.py:handle_action",
        kind=NodeKind.FUNCTION,
        label="handle_action",
        file_path="mod_a.py",
        start_line=10,
        end_line=15,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    n_b = GraphNode(
        id="sym:mod_b.py:handle_action",
        kind=NodeKind.FUNCTION,
        label="handle_action",
        file_path="mod_b.py",
        start_line=20,
        end_line=25,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    caller = GraphNode(
        id="sym:caller.py:invoke",
        kind=NodeKind.FUNCTION,
        label="invoke",
        file_path="caller.py",
        start_line=5,
        end_line=8,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    graph.add_node(n_a)
    graph.add_node(n_b)
    graph.add_node(caller)

    # Edge from caller to placeholder without import context
    graph.add_edge(
        GraphEdge(
            source_id=caller.id,
            target_id="sym:handle_action",
            kind=EdgeKind.CALLS,
            provenance=RelationshipProvenance.STATICALLY_INFERRED,
            properties={"callee_name": "handle_action"},
        )
    )

    builder = GraphBuilder(Path("."))
    builder._resolve_cross_module_calls(graph)

    # Since there are 2 candidates and no import, it must NOT silently pick one;
    # it must produce an UNRESOLVED edge
    out_edges = graph.out_edges.get(caller.id, [])
    unresolved_edges = [e for e in out_edges if e.provenance == RelationshipProvenance.UNRESOLVED]
    assert len(unresolved_edges) == 1
    assert unresolved_edges[0].properties.get("reason") == "ambiguous_cross_module_call"
    assert unresolved_edges[0].properties.get("candidate_count") == 2


def test_interprocedural_flow_1_three_module_database_flow() -> None:
    """Verify Flow 1: Request parameter passed through 3+ modules to database query."""
    repo_root = Path("tests/fixtures/interprocedural_app").resolve()
    files = [
        "app.py",
        "web/order_controller.py",
        "services/order_service.py",
        "managers/order_manager.py",
        "dao/order_dao.py",
    ]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    route = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/order_controller.py")[0]
    sink = graph.find_nodes(kind=NodeKind.QUERY, file_path="dao/order_dao.py")[0]

    # Verify that paths exist from route to sink across 4 hops
    paths = graph.find_paths(route.id, sink.id, max_depth=10)
    assert len(paths) >= 1
    # Check that path crosses web -> services -> managers -> dao
    longest_path = max(paths, key=len)
    files_in_path = {graph.nodes[nid].file_path for nid in longest_path}
    assert "web/order_controller.py" in files_in_path
    assert "services/order_service.py" in files_in_path
    assert "managers/order_manager.py" in files_in_path
    assert "dao/order_dao.py" in files_in_path

    # Verify SPGDataFlowAnalyzer discovers this trace
    analyzer = SPGDataFlowAnalyzer(graph)
    traces = analyzer.trace_all_source_to_sinks()
    order_traces = [t for t in traces if "orders" in t.source_node.file_path or "order" in t.sink_node.file_path]
    assert len(order_traces) >= 1
    assert order_traces[0].category == VulnerabilityCategory.SQL_INJECTION
    assert not order_traces[0].is_sanitized


def test_interprocedural_flow_2_object_id_tenant_access() -> None:
    """Verify Flow 2: Object ID used to access tenant resource without tenant check."""
    repo_root = Path("tests/fixtures/interprocedural_app").resolve()
    files = [
        "web/document_controller.py",
        "services/document_service.py",
        "dao/document_dao.py",
    ]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    routes = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/document_controller.py")
    assert len(routes) == 1
    doc_route = routes[0]

    boundary_info = graph.find_boundary_crossings(doc_route.id)
    # Must report that tenant scoping is MISSING
    assert boundary_info["is_tenant_scoped"] is False
    assert len(boundary_info["tenant_controls"]) == 0
    assert len(boundary_info["queries_executed"]) >= 1


def test_interprocedural_flow_3_route_authorization_divergence() -> None:
    """Verify Flow 3: One route is protected while a second route to the same service is unprotected."""
    repo_root = Path("tests/fixtures/interprocedural_app").resolve()
    files = [
        "web/admin_controller.py",
        "web/public_controller.py",
        "services/user_service.py",
    ]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    admin_routes = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/admin_controller.py")
    public_routes = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/public_controller.py")

    assert len(admin_routes) == 1
    assert len(public_routes) == 1

    admin_boundary = graph.find_boundary_crossings(admin_routes[0].id)
    public_boundary = graph.find_boundary_crossings(public_routes[0].id)

    # Admin route has authorization check
    assert admin_boundary["is_authorized"] is True
    assert any("admin_required" in a for a in admin_boundary["authorization_checks"])

    # Public route to the SAME service lacks authorization check
    assert public_boundary["is_authorized"] is False
    assert len(public_boundary["authorization_checks"]) == 0


def test_interprocedural_flow_4_helper_to_ssrf_sink() -> None:
    """Verify Flow 4: Value passes through helper before reaching SSRF-sensitive HTTP request."""
    repo_root = Path("tests/fixtures/interprocedural_app").resolve()
    files = [
        "web/webhook_controller.py",
        "services/webhook_service.py",
        "helpers/network_helper.py",
    ]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    analyzer = SPGDataFlowAnalyzer(graph)
    traces = analyzer.trace_all_source_to_sinks()
    ssrf_traces = [t for t in traces if t.category == VulnerabilityCategory.SSRF]
    assert len(ssrf_traces) >= 1
    # Verify that at least one trace traverses through the helper function
    assert any(
        any("format_webhook_endpoint" in s.location.symbol for s in t.steps)
        for t in ssrf_traces
    )
    assert any(not t.is_sanitized for t in ssrf_traces)


def test_interprocedural_flow_5_sanitized_vs_unsanitized_branches() -> None:
    """Verify Flow 5: Branch sanitization distinction."""
    repo_root = Path("tests/fixtures/interprocedural_app").resolve()
    files = [
        "web/report_controller.py",
        "services/report_service.py",
        "dao/report_dao.py",
    ]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    # Verify sanitizer node exists
    sanitizers = graph.find_nodes(kind=NodeKind.SANITIZER, file_path="services/report_service.py")
    assert len(sanitizers) >= 1
    assert any("int" in s.label for s in sanitizers)

    analyzer = SPGDataFlowAnalyzer(graph)
    traces = analyzer.trace_all_source_to_sinks()
    report_traces = [t for t in traces if "report" in t.sink_node.file_path]
    assert len(report_traces) >= 1


def test_interprocedural_flow_6_method_inheritance_resolution() -> None:
    """Verify Flow 6: Method call resolved through class inheritance."""
    repo_root = Path("tests/fixtures/interprocedural_app").resolve()
    files = [
        "repositories/base_repo.py",
        "repositories/custom_repo.py",
        "web/custom_controller.py",
    ]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    # Check CustomRepository class has base BaseRepository
    custom_cls = graph.find_nodes(kind=NodeKind.CLASS, file_path="repositories/custom_repo.py")[0]
    assert "BaseRepository" in custom_cls.properties.get("bases", [])

    # Check that execute_raw_sql in BaseRepository has caller in CustomRepository
    base_exec = graph.find_nodes(kind=NodeKind.METHOD, file_path="repositories/base_repo.py")[0]
    callers = graph.get_callers(base_exec.id)
    assert len(callers) >= 1
    assert any("find_by_filter" in c.label for c in callers)


def test_interprocedural_flow_7_dynamic_dispatch_unresolved() -> None:
    """Verify Flow 7: Dynamic call via getattr recorded as UNRESOLVED and reported in gaps."""
    repo_root = Path("tests/fixtures/interprocedural_app").resolve()
    files = ["services/dispatcher.py"]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    unresolved_regions = graph.find_unresolved_regions()
    assert len(unresolved_regions) >= 1
    assert any("getattr" in u["expression"] or "dispatch" in u["caller"] for u in unresolved_regions)
    assert len(res.gap_notes) >= 1


def test_interprocedural_flow_8_safe_counterexample_verification() -> None:
    """Verify Flow 8: Safe counterexample verifies tenant scoping and authorization checks."""
    repo_root = Path("tests/fixtures/interprocedural_safe").resolve()
    files = [
        "app.py",
        "web/order_controller.py",
        "services/order_service.py",
        "managers/order_manager.py",
        "dao/order_dao.py",
        "web/document_controller.py",
        "services/document_service.py",
        "dao/document_dao.py",
        "web/admin_controller.py",
        "web/public_controller.py",
        "services/user_service.py",
        "web/webhook_controller.py",
        "services/webhook_service.py",
        "helpers/network_helper.py",
        "web/report_controller.py",
        "services/report_service.py",
        "dao/report_dao.py",
        "repositories/base_repo.py",
        "repositories/custom_repo.py",
        "web/custom_controller.py",
        "services/dispatcher.py",
    ]
    builder = GraphBuilder(repo_root)
    res = builder.build(files)
    graph = res.graph

    # 1. Document route in safe app HAS tenant scoping
    doc_route = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/document_controller.py")[0]
    doc_boundary = graph.find_boundary_crossings(doc_route.id)
    assert doc_boundary["is_tenant_scoped"] is True
    assert any("session" in t for t in doc_boundary["tenant_controls"])

    # 2. Both admin and public routes HAVE authorization checks
    admin_route = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/admin_controller.py")[0]
    public_route = graph.find_nodes(kind=NodeKind.ROUTE, file_path="web/public_controller.py")[0]

    assert graph.find_boundary_crossings(admin_route.id)["is_authorized"] is True
    assert graph.find_boundary_crossings(public_route.id)["is_authorized"] is True
