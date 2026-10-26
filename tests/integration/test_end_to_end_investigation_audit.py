"""End-to-end MCP JSON-RPC tool verification and realistic security investigation audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from semantiq.integrations.mcp.server import MCPServer


@pytest.mark.anyio
async def test_mcp_error_handling_and_bounded_output() -> None:
    """Verify MCP tools handle invalid paths, missing symbols, and bounded limits safely."""
    server = MCPServer()

    # 1. Non-existent path returns error or empty result gracefully without crashing
    bad_req = {
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "semantiq_query_symbols",
            "arguments": {"path": "C:/non_existent_directory_for_audit_test", "query": "document"},
        },
    }
    bad_resp = await server.handle_request(bad_req)
    assert bad_resp is not None
    # Must either be an error response or content returning empty/error string
    assert "error" in bad_resp or "result" in bad_resp

    # 2. Unknown symbol returns empty list without crashing
    sym_req = {
        "jsonrpc": "2.0",
        "id": 102,
        "method": "tools/call",
        "params": {
            "name": "semantiq_query_symbols",
            "arguments": {
                "path": str(Path("tests/fixtures/interprocedural_app").resolve()),
                "query": "non_existent_symbol_xyz",
            },
        },
    }
    sym_resp = await server.handle_request(sym_req)
    assert sym_resp is not None
    data = json.loads(sym_resp["result"]["content"][0]["text"])
    assert isinstance(data, list)
    assert len(data) == 0

    # 3. Bounded output: limit=2 returns at most 2 items
    bounded_req = {
        "jsonrpc": "2.0",
        "id": 103,
        "method": "tools/call",
        "params": {
            "name": "semantiq_query_symbols",
            "arguments": {
                "path": str(Path("tests/fixtures/interprocedural_app").resolve()),
                "query": "view",
                "limit": 2,
            },
        },
    }
    bounded_resp = await server.handle_request(bounded_req)
    assert bounded_resp is not None
    b_data = json.loads(bounded_resp["result"]["content"][0]["text"])
    assert isinstance(b_data, list)
    assert len(b_data) <= 2


@pytest.mark.anyio
async def test_end_to_end_agent_investigation_workflow() -> None:
    """Simulate an autonomous security investigation using MCP tools on multi-file vulnerable vs patched apps.

    Workflow:
    1. Discover routes & reachability.
    2. Inspect tenant isolation & object-level access.
    3. Trace interprocedural parameter flow across layers.
    4. Inspect authorization controls & detect bypass.
    5. Expose analysis gaps (dynamic calls).
    6. Record structured hypothesis.
    7. Compare with safe application and verify correct distinction.
    """
    server = MCPServer()
    vuln_path = str(Path("tests/fixtures/interprocedural_app").resolve())
    safe_path = str(Path("tests/fixtures/interprocedural_safe").resolve())

    # Step 1: Discover routes
    routes_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "semantiq_query_route_reachability", "arguments": {"path": vuln_path}},
    }
    routes_resp = await server.handle_request(routes_req)
    assert routes_resp is not None
    routes = json.loads(routes_resp["result"]["content"][0]["text"])
    assert len(routes) >= 5
    route_paths = [r["route_path"] for r in routes]
    assert "/api/v1/documents/<doc_id>" in route_paths
    assert "/api/v1/orders/search" in route_paths
    assert "/api/v1/public/delete_user" in route_paths

    # Step 2: Query tenant isolation on vulnerable app
    tenant_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "semantiq_query_tenant_isolation", "arguments": {"path": vuln_path}},
    }
    tenant_resp = await server.handle_request(tenant_req)
    assert tenant_resp is not None
    tenant_results = json.loads(tenant_resp["result"]["content"][0]["text"])
    assert len(tenant_results) >= 1

    doc_item = [t for t in tenant_results if "documents" in t["route_path"]][0]
    # In vulnerable app, document access lacks ownership/tenant guard
    assert doc_item["has_ownership_guard"] is False
    assert len(doc_item["queries"]) >= 1

    # Step 3: Inspect authorization path on vulnerable app
    auth_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "semantiq_query_authorization_path", "arguments": {"path": vuln_path}},
    }
    auth_resp = await server.handle_request(auth_req)
    assert auth_resp is not None
    auth_results = json.loads(auth_resp["result"]["content"][0]["text"])
    # Public delete route has no authorization check
    public_delete = [a for a in auth_results if "public/delete_user" in a["route_path"]][0]
    assert public_delete["is_authorized"] is False

    # Step 4: Trace interprocedural dataflow
    df_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "semantiq_query_dataflow_path", "arguments": {"path": vuln_path}},
    }
    df_resp = await server.handle_request(df_req)
    assert df_resp is not None
    df_traces = json.loads(df_resp["result"]["content"][0]["text"])
    assert len(df_traces) >= 1
    # Check that search query traces to database sink
    order_trace = [t for t in df_traces if "order" in t["source"]["file_path"] or "query" in t["source"]["label"]][0]
    assert order_trace["category"] == "sql_injection"
    assert order_trace["is_sanitized"] is False
    assert len(order_trace["steps"]) >= 4

    # Step 5: Query analysis gaps
    gap_req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "semantiq_get_analysis_gaps", "arguments": {"path": vuln_path}},
    }
    gap_resp = await server.handle_request(gap_req)
    assert gap_resp is not None
    gaps = json.loads(gap_resp["result"]["content"][0]["text"])
    assert gaps["total_unresolved"] >= 1
    assert any("getattr" in u["expression"] or "dispatch" in u["caller"] for u in gaps["unresolved_dynamic_calls"])

    # Step 6: Formulate and record hypothesis
    hyp_req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "semantiq_record_hypothesis",
            "arguments": {
                "path": vuln_path,
                "statement": "Missing tenant isolation on document_view allows cross-tenant document access",
                "target_symbol": "document_view",
                "entry_point": "/api/v1/documents/<doc_id>",
                "rule_id": "SQ-PY-015",
                "disposition": "confirmed",
            },
        },
    }
    hyp_resp = await server.handle_request(hyp_req)
    assert hyp_resp is not None
    hyp_result = json.loads(hyp_resp["result"]["content"][0]["text"])
    assert hyp_result["target_symbol"] == "document_view"
    assert hyp_result["disposition"] == "confirmed"

    # Step 7: Compare with patched safe application
    safe_tenant_req = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "semantiq_query_tenant_isolation", "arguments": {"path": safe_path}},
    }
    safe_tenant_resp = await server.handle_request(safe_tenant_req)
    assert safe_tenant_resp is not None
    safe_tenant_results = json.loads(safe_tenant_resp["result"]["content"][0]["text"])

    safe_doc = [t for t in safe_tenant_results if "documents" in t["route_path"]][0]
    # In safe app, document access HAS genuine tenant isolation guard!
    assert safe_doc["has_ownership_guard"] is True

    # Safe public delete route is also protected
    safe_auth_req = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": "semantiq_query_authorization_path", "arguments": {"path": safe_path}},
    }
    safe_auth_resp = await server.handle_request(safe_auth_req)
    assert safe_auth_resp is not None
    safe_auth_results = json.loads(safe_auth_resp["result"]["content"][0]["text"])
    safe_public_delete = [a for a in safe_auth_results if "public/delete_user" in a["route_path"]][0]
    assert safe_public_delete["is_authorized"] is True
