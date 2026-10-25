"""Integration test for Model Context Protocol (MCP) server."""

import asyncio
from pathlib import Path

from semantiq.client import Semantiq
from semantiq.config import SemantiqConfig
from semantiq.integrations.mcp.server import MCPServer


def test_mcp_server_protocol(vulnerable_app_dir: Path) -> None:
    async def _test() -> None:
        cfg = SemantiqConfig()
        cfg.storage.database_path = ":memory:"
        client = Semantiq(config=cfg)
        server = MCPServer(security_client=client)

        # 1. Initialize
        init_req = {"method": "initialize", "id": 1, "jsonrpc": "2.0"}
        init_res = await server.handle_request(init_req)
        assert init_res["result"]["serverInfo"]["name"] == "semantiq"

        # 2. Tools list
        list_req = {"method": "tools/list", "id": 2, "jsonrpc": "2.0"}
        list_res = await server.handle_request(list_req)
        tool_names = [t["name"] for t in list_res["result"]["tools"]]
        assert "semantiq_scan_repository" in tool_names
        assert "semantiq_inspect_repository" in tool_names
        assert "semantiq_build_threat_model" in tool_names

        # 3. Tool call
        call_req = {
            "method": "tools/call",
            "id": 3,
            "jsonrpc": "2.0",
            "params": {
                "name": "semantiq_inspect_repository",
                "arguments": {"path": str(vulnerable_app_dir)},
            },
        }
        call_res = await server.handle_request(call_req)
        assert call_res["result"]["content"][0]["type"] == "text"
        assert "in_scope_files" in call_res["result"]["content"][0]["text"]

    asyncio.run(_test())
