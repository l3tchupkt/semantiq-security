"""Model Context Protocol (MCP) stdio server implementation."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from semantiq.client import Semantiq
from semantiq.models import ValidationMode

MCP_PROTOCOL_VERSION = "2024-11-05"

TOOLS_MANIFEST = [
    {
        "name": "semantiq_inspect_repository",
        "description": "Inspect repository structure, detect languages, Git metadata, and file inventory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_build_threat_model",
        "description": "Extract application entry points, trust boundaries, and sensitive sinks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_scan_repository",
        "description": "Execute deterministic security scan over repository with optional category focus.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Local target directory path"},
                "focus": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of vulnerability classes (e.g. sql-injection, command-injection)"
                },
                "mode": {"type": "string", "enum": ["standard", "deep"], "default": "standard"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "semantiq_scan_diff",
        "description": "Analyze pull-request or branch changes between two Git revisions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Local Git repository path"},
                "base": {"type": "string", "description": "Base Git commit or branch (e.g. origin/main)"},
                "head": {"type": "string", "description": "Optional head Git commit or branch (defaults to HEAD)"}
            },
            "required": ["target", "base"]
        }
    },
    {
        "name": "semantiq_get_findings",
        "description": "Retrieve security findings associated with a specific scan ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Unique scan ID"}
            },
            "required": ["scan_id"]
        }
    },
    {
        "name": "semantiq_investigate_finding",
        "description": "Perform deeper analysis on a specific finding using local context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Target finding ID"}
            },
            "required": ["finding_id"]
        }
    },
    {
        "name": "semantiq_validate_finding",
        "description": "Validate finding using static dataflow (static), test fixtures (test_based), or manual plan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Target finding ID"},
                "mode": {"type": "string", "enum": ["static", "test_based", "dynamic_sandbox", "manual_plan"], "default": "static"}
            },
            "required": ["finding_id"]
        }
    },
    {
        "name": "semantiq_propose_patch",
        "description": "Generate a unified diff patch enforcing security invariants for a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Target finding ID"}
            },
            "required": ["finding_id"]
        }
    },
    {
        "name": "semantiq_verify_patch",
        "description": "Verify proposed patch in an isolated temporary copy without modifying working tree.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Target finding ID"}
            },
            "required": ["finding_id"]
        }
    },
    {
        "name": "semantiq_export_report",
        "description": "Export scan results in JSON, Markdown, or SARIF 2.1.0 format.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Target scan ID"},
                "format": {"type": "string", "enum": ["json", "markdown", "sarif"], "default": "json"}
            },
            "required": ["scan_id"]
        }
    }
]


class MCPServer:
    """Stdio JSON-RPC 2.0 server providing MCP tool interfaces."""

    def __init__(self, security_client: Semantiq | None = None) -> None:
        self.security = security_client or Semantiq()

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        method = request.get("method")
        msg_id = request.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "semantiq", "version": "0.1.0"}
                }
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS_MANIFEST}
            }

        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {})
            try:
                result = await self._dispatch_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(result, indent=2, default=str)}
                        ]
                    }
                }
            except Exception as error:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32603, "message": str(error)}
                }

        elif method == "notifications/initialized":
            return None

        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found."}
            }

    async def _dispatch_tool(self, name: str, args: dict[str, Any]) -> Any:
        if name == "semantiq_inspect_repository":
            insp = await self.security.inspect_repository(args["path"])
            return insp.model_dump()

        elif name == "semantiq_build_threat_model":
            tm = await self.security.build_threat_model(args["path"])
            return tm.model_dump()

        elif name == "semantiq_scan_repository":
            res = await self.security.scan(
                target=args["target"],
                focus=args.get("focus"),
                mode=args.get("mode", "standard"),
            )
            return res.model_dump()

        elif name == "semantiq_scan_diff":
            res = await self.security.scan_diff(
                target=args["target"],
                base=args["base"],
                head=args.get("head"),
            )
            return res.model_dump()

        elif name == "semantiq_get_findings":
            findings = await self.security.get_findings(args["scan_id"])
            return [f.model_dump() for f in findings]

        elif name == "semantiq_investigate_finding":
            inv = await self.security.investigate(args["finding_id"])
            return inv

        elif name == "semantiq_validate_finding":
            mode_str = args.get("mode", "static")
            val_res = await self.security.validate(args["finding_id"], mode=ValidationMode(mode_str))
            return val_res.model_dump()

        elif name == "semantiq_propose_patch":
            patch = await self.security.propose_patch(args["finding_id"])
            return patch.model_dump()

        elif name == "semantiq_verify_patch":
            ver = await self.security.verify_patch(args["finding_id"])
            return ver.model_dump()

        elif name == "semantiq_export_report":
            report = await self.security.export_report(args["scan_id"], format=args.get("format", "json"))
            return {"report": report}

        else:
            raise ValueError(f"Unknown MCP tool: {name}")

    async def run_stdio(self) -> None:
        """Run stdio listener loop."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break

            text = line.decode("utf-8").strip()
            if not text:
                continue

            try:
                request = json.loads(text)
                response = await self.handle_request(request)
                if response:
                    out = json.dumps(response)
                    sys.stdout.write(f"{out}\n")
                    sys.stdout.flush()
            except Exception as error:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {error}"}
                }
                sys.stdout.write(f"{json.dumps(err_resp)}\n")
                sys.stdout.flush()
