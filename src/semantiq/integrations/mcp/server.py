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
    },
    {
        "name": "semantiq_query_symbols",
        "description": "Search and inspect symbols in the Semantic Program Graph (functions, classes, routes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "query": {"type": "string", "description": "Symbol name or substring filter"},
                "kind": {"type": "string", "description": "Node kind filter (function, class, route, query, etc.)"},
                "file_path": {"type": "string", "description": "Filter by file path"},
                "limit": {"type": "integer", "default": 25, "description": "Maximum number of symbols to return"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_query_callers_callees",
        "description": "Lookup callers and callees for a specified symbol in the Semantic Program Graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "symbol_name": {"type": "string", "description": "Symbol name to look up"},
                "direction": {"type": "string", "enum": ["callers", "callees", "both"], "default": "both"}
            },
            "required": ["path", "symbol_name"]
        }
    },
    {
        "name": "semantiq_query_neighborhood",
        "description": "Extract a bounded subgraph neighborhood around a node in the Semantic Program Graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "node_id": {"type": "string", "description": "Node identifier to center neighborhood on"},
                "radius": {"type": "integer", "default": 1, "description": "Search radius (1 to 3 hops)"}
            },
            "required": ["path", "node_id"]
        }
    },
    {
        "name": "semantiq_query_dataflow_path",
        "description": "Trace interprocedural dataflow paths from route parameters to sensitive operations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "source_symbol": {"type": "string", "description": "Optional source parameter or function name"},
                "sink_category": {"type": "string", "description": "Optional vulnerability category (e.g. sql_injection, ssrf)"},
                "max_depth": {"type": "integer", "default": 10, "description": "Maximum path traversal depth"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_query_route_reachability",
        "description": "Discover reachability chains from HTTP routes to sensitive operations in the codebase.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "route_path": {"type": "string", "description": "Optional route path pattern to filter by"},
                "sink_kind": {"type": "string", "description": "Optional sink kind (query, process_exec, external_request)"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_query_authorization_path",
        "description": "Inspect authentication boundaries, authorization decorators, and sensitive queries for routes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "route_path": {"type": "string", "description": "Optional route path pattern"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_query_tenant_isolation",
        "description": "Inspect resource access paths with and without tenant ownership enforcement.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "with_ownership_check": {"type": "boolean", "description": "Filter by presence of ownership checks"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_query_async_flows",
        "description": "Inspect evidence-backed asynchronous message boundaries, queues, and background worker flows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "component": {"type": "string", "description": "Optional component or symbol name filter"},
                "queue": {"type": "string", "description": "Optional queue name filter"},
                "unverified_only": {"type": "boolean", "description": "Filter for unverified/dynamic flows"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_query_worker_authorization",
        "description": "Inspect consumer-side authorization, caller identity trust, and tenant isolation in background workers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "worker_symbol": {"type": "string", "description": "Optional worker function or handler symbol name to inspect"},
                "queue_name": {"type": "string", "description": "Optional queue name to filter"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_query_idempotency_and_concurrency",
        "description": "Inspect concurrency controls, idempotency guards, and retry hazards across message queues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "entity": {"type": "string", "description": "Optional entity or domain concept (e.g. 'refund', 'order', 'payment', 'task')"},
                "queue_name": {"type": "string", "description": "Optional queue name to inspect"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_resolve_dependency_symbol",
        "description": "Resolve external or cross-package symbols across package boundaries without executing code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "symbol_path": {"type": "string", "description": "Fully-qualified symbol name (e.g. 'ait.core.server.plugin.Plugin')"}
            },
            "required": ["path", "symbol_path"]
        }
    },
    {
        "name": "semantiq_get_dependency_source",
        "description": "Retrieve bounded source code lines from an external dependency or imported package.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "symbol_or_path": {"type": "string", "description": "Module import path or dependency file path"},
                "start_line": {"type": "integer", "description": "Starting line number (1-indexed)"},
                "end_line": {"type": "integer", "description": "Ending line number (inclusive)"},
                "max_lines": {"type": "integer", "default": 50, "description": "Maximum number of lines to return"}
            },
            "required": ["path", "symbol_or_path", "start_line", "end_line"]
        }
    },
    {
        "name": "semantiq_query_security_primitives",
        "description": "Inspect security primitives (session IDs, tokens, CSRF hooks, nonces) and evaluate entropy source and cookie flags.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "kind": {
                    "type": "string",
                    "enum": ["session_identifier", "api_token", "csrf_token", "password_reset_token", "auth_secret", "crypto_nonce"],
                    "description": "Optional primitive category filter"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_get_analysis_gaps",
        "description": "Retrieve unresolved dynamic dispatch sites, unparsed files, and unsupported syntax notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_record_hypothesis",
        "description": "Record a structured vulnerability hypothesis into persistent repository memory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "statement": {"type": "string", "description": "Hypothesis claim or proposition"},
                "target_symbol": {"type": "string", "description": "Symbol under investigation"},
                "entry_point": {"type": "string", "description": "Application entry point"},
                "rule_id": {"type": "string", "description": "Vulnerability rule identifier"},
                "disposition": {"type": "string", "enum": ["open", "confirmed", "mitigated", "false_positive"], "default": "open"}
            },
            "required": ["path", "statement", "target_symbol", "entry_point", "rule_id"]
        }
    },
    {
        "name": "semantiq_get_evidence",
        "description": "Retrieve verifiable source snippets, citations, and dataflow steps for a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Target finding ID"}
            },
            "required": ["finding_id"]
        }
    },
    {
        "name": "semantiq_get_source_excerpt",
        "description": "Retrieve bounded source code lines and syntax details for code inspection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "file_path": {"type": "string", "description": "File path relative to repository root"},
                "start_line": {"type": "integer", "description": "Starting line number (1-indexed)"},
                "end_line": {"type": "integer", "description": "Ending line number (inclusive)"},
                "max_lines": {"type": "integer", "default": 50, "description": "Maximum number of lines to return"}
            },
            "required": ["path", "file_path", "start_line", "end_line"]
        }
    },
    {
        "name": "semantiq_query_attack_chains",
        "description": "Discover multi-step cross-component attack chains from routes to sensitive operations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "max_depth": {"type": "integer", "default": 8, "description": "Maximum traversal depth"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_resolve_symbol",
        "description": "Statically resolve a symbol with exact file, line bounds, MRO, parameters, and provenance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "symbol": {"type": "string", "description": "Symbol name or qualified path"}
            },
            "required": ["path", "symbol"]
        }
    },
    {
        "name": "semantiq_trace_argument_into_callee",
        "description": "Trace caller argument mapping into callee parameters and internal sensitive sinks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "caller_symbol": {"type": "string", "description": "Calling function or method symbol"},
                "callee_symbol": {"type": "string", "description": "Target callee function or method symbol"},
                "argument": {"type": "string", "description": "Optional argument name or index (0-based)"}
            },
            "required": ["path", "caller_symbol", "callee_symbol"]
        }
    },
    {
        "name": "semantiq_trace_return_to_caller",
        "description": "Trace return expressions from a callee back into caller receiving variables.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "callee_symbol": {"type": "string", "description": "Callee function or method symbol"},
                "caller_symbol": {"type": "string", "description": "Optional caller function symbol filter"}
            },
            "required": ["path", "callee_symbol"]
        }
    },
    {
        "name": "semantiq_find_routes_reaching_sensitive_operation",
        "description": "Find all HTTP/WebSocket routes reaching a sensitive sink with guarded vs unguarded comparison.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "sink_kind": {"type": "string", "description": "Optional sink category (query, process_exec, file_operation, external_request)"},
                "route_filter": {"type": "string", "description": "Optional route path pattern filter"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_identify_authorization_checks",
        "description": "Inspect enforced, bypassed, and unresolved security guards protecting an entry point.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "target": {"type": "string", "description": "Route path or function symbol to inspect"}
            },
            "required": ["path", "target"]
        }
    },
    {
        "name": "semantiq_show_unresolved_dynamic_dispatch",
        "description": "Extract all unresolved dynamic dispatches, getattr/setattr calls, and reflection sites.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_get_interprocedural_evidence_path",
        "description": "Retrieve an ordered, verified causal execution path mapped directly to Phase 1 semantic roles.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "source_entry": {"type": "string", "description": "Originating route or entry handler"},
                "sink": {"type": "string", "description": "Target sensitive sink expression, ID, or kind"}
            },
            "required": ["path", "source_entry", "sink"]
        }
    },
    {
        "name": "semantiq_finalize_scan_contract",
        "description": "Deterministically finalize findings, validate citations, evaluate proof gaps, and produce sealed SARIF 2.1.0 contract.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "scan_id": {"type": "string", "description": "Optional scan ID to finalize from storage"},
                "findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Optional list of findings to finalize directly"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_list_investigation_packets",
        "description": "Partition repository attack surface into bounded, prioritized investigation packets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_run_parallel_investigation",
        "description": "Execute bounded parallel multi-perspective investigation across specialized workers (Discovery, Dataflow, Authorization, Adversarial).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local repository directory path"},
                "max_workers": {"type": "integer", "description": "Maximum concurrent workers (default 3)", "default": 3},
                "include_adversarial": {"type": "boolean", "description": "Enable adversarial verification worker", "default": True},
                "timeout_seconds": {"type": "number", "description": "Global timeout in seconds", "default": 120.0}
            },
            "required": ["path"]
        }
    },
    {
        "name": "semantiq_get_coordinator_status",
        "description": "Retrieve coordinator execution runs, packet assignments, worker states, and reducer decisions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string", "description": "Optional investigation run ID"}
            }
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
            valid_tool_names = {t["name"] for t in TOOLS_MANIFEST}
            if tool_name not in valid_tool_names:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found."}
                }
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

        elif name == "semantiq_query_symbols":
            return await self.security.query_symbols(
                target=args["path"],
                query=args.get("query"),
                kind=args.get("kind"),
                file_path=args.get("file_path"),
                limit=args.get("limit", 25),
            )

        elif name == "semantiq_query_callers_callees":
            return await self.security.query_callers_callees(
                target=args["path"],
                symbol_name=args["symbol_name"],
                direction=args.get("direction", "both"),
            )

        elif name == "semantiq_query_neighborhood":
            return await self.security.query_neighborhood(
                target=args["path"],
                node_id=args["node_id"],
                radius=args.get("radius", 1),
            )

        elif name == "semantiq_query_dataflow_path":
            return await self.security.query_dataflow_paths(
                target=args["path"],
                source_symbol=args.get("source_symbol"),
                sink_category=args.get("sink_category"),
                max_depth=args.get("max_depth", 10),
            )

        elif name == "semantiq_query_route_reachability":
            return await self.security.query_route_reachability(
                target=args["path"],
                route_path=args.get("route_path"),
                sink_kind=args.get("sink_kind"),
            )

        elif name == "semantiq_query_authorization_path":
            return await self.security.query_authorization_path(
                target=args["path"],
                route_path=args.get("route_path"),
            )

        elif name == "semantiq_query_tenant_isolation":
            return await self.security.query_tenant_isolation(
                target=args["path"],
                with_ownership_check=args.get("with_ownership_check"),
            )

        elif name == "semantiq_query_async_flows":
            return await self.security.query_async_flows(
                target=args["path"],
                component=args.get("component"),
                queue=args.get("queue"),
                unverified_only=args.get("unverified_only", False),
            )

        elif name == "semantiq_query_worker_authorization":
            return await self.security.query_worker_authorization(
                target=args["path"],
                worker_symbol=args.get("worker_symbol"),
                queue_name=args.get("queue_name"),
            )

        elif name == "semantiq_query_idempotency_and_concurrency":
            return await self.security.query_idempotency_and_concurrency(
                target=args["path"],
                entity=args.get("entity"),
                queue_name=args.get("queue_name"),
            )

        elif name == "semantiq_resolve_dependency_symbol":
            return await self.security.resolve_dependency_symbol(
                target=args["path"],
                symbol_path=args["symbol_path"],
            )

        elif name == "semantiq_get_dependency_source":
            return await self.security.get_dependency_source(
                target=args["path"],
                symbol_or_path=args["symbol_or_path"],
                start_line=args["start_line"],
                end_line=args["end_line"],
                max_lines=args.get("max_lines", 50),
            )

        elif name == "semantiq_query_security_primitives":
            return await self.security.query_security_primitives(
                target=args["path"],
                kind=args.get("kind"),
            )

        elif name == "semantiq_get_analysis_gaps":
            return await self.security.get_analysis_gaps(args["path"])

        elif name == "semantiq_record_hypothesis":
            return await self.security.record_hypothesis(
                target=args["path"],
                statement=args["statement"],
                target_symbol=args["target_symbol"],
                entry_point=args["entry_point"],
                rule_id=args["rule_id"],
                disposition=args.get("disposition", "open"),
            )

        elif name == "semantiq_get_evidence":
            return await self.security.get_evidence(args["finding_id"])

        elif name == "semantiq_get_source_excerpt":
            return await self.security.get_source_excerpt(
                target=args["path"],
                file_path=args["file_path"],
                start_line=args["start_line"],
                end_line=args["end_line"],
                max_lines=args.get("max_lines", 50),
            )

        elif name == "semantiq_query_attack_chains":
            return await self.security.query_attack_chains(
                target=args["path"],
                max_depth=args.get("max_depth", 8),
            )

        elif name == "semantiq_resolve_symbol":
            return await self.security.resolve_symbol(
                target=args["path"],
                symbol=args["symbol"],
            )

        elif name == "semantiq_trace_argument_into_callee":
            return await self.security.trace_argument_into_callee(
                target=args["path"],
                caller_symbol=args["caller_symbol"],
                callee_symbol=args["callee_symbol"],
                argument=args.get("argument"),
            )

        elif name == "semantiq_trace_return_to_caller":
            return await self.security.trace_return_to_caller(
                target=args["path"],
                callee_symbol=args["callee_symbol"],
                caller_symbol=args.get("caller_symbol"),
            )

        elif name == "semantiq_find_routes_reaching_sensitive_operation":
            return await self.security.find_routes_reaching_sensitive_operation(
                target=args["path"],
                sink_kind=args.get("sink_kind"),
                route_filter=args.get("route_filter"),
            )

        elif name == "semantiq_identify_authorization_checks":
            return await self.security.identify_authorization_checks(
                target=args["path"],
                target_symbol=args["target"],
            )

        elif name == "semantiq_show_unresolved_dynamic_dispatch":
            return await self.security.show_unresolved_dynamic_dispatch(
                target=args["path"],
            )

        elif name == "semantiq_get_interprocedural_evidence_path":
            return await self.security.get_interprocedural_evidence_path(
                target=args["path"],
                source_entry=args["source_entry"],
                sink=args["sink"],
            )

        elif name == "semantiq_finalize_scan_contract":
            return await self.security.finalize_scan_contract(
                target=args["path"],
                scan_id=args.get("scan_id"),
                findings=args.get("findings"),
            )

        elif name == "semantiq_list_investigation_packets":
            return await self.security.list_investigation_packets(target=args["path"])

        elif name == "semantiq_run_parallel_investigation":
            return await self.security.run_parallel_investigation(
                target=args["path"],
                max_workers=args.get("max_workers", 3),
                include_adversarial=args.get("include_adversarial", True),
                timeout_seconds=float(args.get("timeout_seconds", 120.0)),
            )

        elif name == "semantiq_get_coordinator_status":
            return await self.security.get_coordinator_status(run_id=args.get("run_id"))

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
