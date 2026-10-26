"""Integration tests for MCP graph query tools on real fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from semantiq.integrations.mcp.server import MCPServer


@pytest.mark.anyio
async def test_mcp_graph_query_tools() -> None:
    server = MCPServer()
    fixture_path = str(Path("tests/fixtures/multitenant_saas_app").resolve())

    # 1. Test tools/list includes new tools
    list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    list_resp = await server.handle_request(list_req)
    assert list_resp is not None
    tool_names = [t["name"] for t in list_resp["result"]["tools"]]
    assert "semantiq_query_symbols" in tool_names
    assert "semantiq_query_callers_callees" in tool_names
    assert "semantiq_query_neighborhood" in tool_names
    assert "semantiq_query_dataflow_path" in tool_names
    assert "semantiq_query_route_reachability" in tool_names
    assert "semantiq_query_authorization_path" in tool_names
    assert "semantiq_query_tenant_isolation" in tool_names
    assert "semantiq_get_analysis_gaps" in tool_names
    assert "semantiq_record_hypothesis" in tool_names

    # 2. Test semantiq_query_symbols
    sym_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "semantiq_query_symbols",
            "arguments": {"path": fixture_path, "query": "document", "limit": 10},
        },
    }
    sym_resp = await server.handle_request(sym_req)
    assert sym_resp is not None
    sym_data = json.loads(sym_resp["result"]["content"][0]["text"])
    assert isinstance(sym_data, list)
    assert len(sym_data) >= 1
    assert any("document" in s["label"].lower() for s in sym_data)

    # 3. Test semantiq_query_route_reachability
    reach_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "semantiq_query_route_reachability",
            "arguments": {"path": fixture_path},
        },
    }
    reach_resp = await server.handle_request(reach_req)
    assert reach_resp is not None
    reach_data = json.loads(reach_resp["result"]["content"][0]["text"])
    assert isinstance(reach_data, list)
    assert len(reach_data) >= 1

    # 4. Test semantiq_query_authorization_path
    auth_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "semantiq_query_authorization_path",
            "arguments": {"path": fixture_path},
        },
    }
    auth_resp = await server.handle_request(auth_req)
    assert auth_resp is not None
    auth_data = json.loads(auth_resp["result"]["content"][0]["text"])
    assert isinstance(auth_data, list)
    assert len(auth_data) >= 1

    # 5. Test semantiq_query_tenant_isolation
    tenant_req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "semantiq_query_tenant_isolation",
            "arguments": {"path": fixture_path},
        },
    }
    tenant_resp = await server.handle_request(tenant_req)
    assert tenant_resp is not None
    tenant_data = json.loads(tenant_resp["result"]["content"][0]["text"])
    assert isinstance(tenant_data, list)
    assert len(tenant_data) >= 1

    # 6. Test semantiq_get_analysis_gaps
    gap_req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "semantiq_get_analysis_gaps",
            "arguments": {"path": fixture_path},
        },
    }
    gap_resp = await server.handle_request(gap_req)
    assert gap_resp is not None
    gap_data = json.loads(gap_resp["result"]["content"][0]["text"])
    assert "unresolved_dynamic_calls" in gap_data

    # 7. Test semantiq_record_hypothesis
    hyp_req = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "semantiq_record_hypothesis",
            "arguments": {
                "path": fixture_path,
                "statement": "Missing tenant isolation on document_view allows cross-tenant data leakage",
                "target_symbol": "document_view",
                "entry_point": "/api/v1/tenant/documents/<doc_id>",
                "rule_id": "SQ-PY-015",
                "disposition": "confirmed",
            },
        },
    }
    hyp_resp = await server.handle_request(hyp_req)
    assert hyp_resp is not None
    hyp_data = json.loads(hyp_resp["result"]["content"][0]["text"])
    assert hyp_data["target_symbol"] == "document_view"
    assert hyp_data["disposition"] == "confirmed"
