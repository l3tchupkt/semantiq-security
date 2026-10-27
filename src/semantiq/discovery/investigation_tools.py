"""Bounded, structured investigation tools for autonomous AI vulnerability discovery.

Provides structured tool specifications and an execution dispatcher that connects model
tool calls directly to the Semantic Program Graph (SPG), repository intelligence,
safe file reading, and hypothesis tracking.
"""

from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, NodeKind
from semantiq.models import (
    AttackChain,
    AttackChainStep,
    CodeEvidence,
    ConfidenceLevel,
    DataFlowStep,
    Finding,
    InvestigationHypothesis,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.providers.base import ToolDefinition
from semantiq.providers.verifier import verify_finding_citations
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.repository.safepath import resolve_safe_path
from semantiq.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


INVESTIGATION_TOOLS: list[ToolDefinition] = [
    ToolDefinition(
        name="get_repository_overview",
        description=(
            "Retrieve high-level architectural overview: repository files, routes/entry points, "
            "sensitive sinks, security boundaries, and unresolved dispatch areas."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="list_repository_files",
        description="List repository files and directory structure in scope for security investigation.",
        parameters={
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Optional directory path to filter (e.g. 'api', 'services'). If omitted, lists all repository files.",
                },
            },
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="get_source_excerpt",
        description=(
            "Retrieve exact source code excerpt for a file between start_line and end_line with line numbers, "
            "or by function/symbol name. Use this to inspect implementations, verify data-flow propagation, check guards, "
            "or confirm citations."
        ),
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Relative repository file path"},
                "symbol": {"type": "string", "description": "Optional function, method, or class name to auto-locate"},
                "start_line": {"type": "integer", "description": "1-based starting line number (optional if symbol provided)"},
                "end_line": {"type": "integer", "description": "1-based ending line number (optional if symbol provided)"},
                "max_lines": {"type": "integer", "description": "Maximum lines to retrieve (default: 50, max: 100)"},
            },
            "required": ["file_path"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="query_symbols",
        description="Search for functions, methods, classes, or variables matching a query name across files.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Symbol name or substring to search"},
                "file_path": {"type": "string", "description": "Optional file path to limit scope"},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="query_callers_callees",
        description="Explore incoming callers and outgoing callees for a specified function or symbol.",
        parameters={
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "Function or method symbol name"},
                "direction": {
                    "type": "string",
                    "enum": ["callers", "callees", "both"],
                    "description": "Exploration direction (default: 'both')",
                },
            },
            "required": ["symbol"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="query_dataflow_path",
        description=(
            "Trace data-flow paths from a source expression or parameter to a sink operation across functions. "
            "Reports unresolved dynamic dispatch and warns when missing edges do not prove safety."
        ),
        parameters={
            "type": "object",
            "properties": {
                "source_symbol": {"type": "string", "description": "Originating source symbol or parameter"},
                "sink_symbol": {"type": "string", "description": "Target sink symbol or operation"},
            },
            "required": ["source_symbol", "sink_symbol"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="query_route_reachability",
        description=(
            "Inspect a specific HTTP/API route entry point, its handler, applied middleware, "
            "authentication status, and directly reachable database queries or sensitive sinks."
        ),
        parameters={
            "type": "object",
            "properties": {
                "route_path": {"type": "string", "description": "HTTP route path (e.g. '/api/v1/...')"},
            },
            "required": ["route_path"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="query_authorization_boundary",
        description=(
            "Analyze authentication, authorization, role enforcement, and tenant isolation for a route or symbol. "
            "Identifies whether checks occur before or after sensitive actions."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Route path or function symbol to inspect"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="query_alternate_entry_points",
        description=(
            "Find all routes or entry points that can reach a sensitive operation or sink. "
            "Critical for finding authorization divergence where one route is guarded and another is exposed."
        ),
        parameters={
            "type": "object",
            "properties": {
                "sink_symbol": {"type": "string", "description": "Name or kind of sensitive sink operation"},
            },
            "required": ["sink_symbol"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="get_analysis_gaps",
        description=(
            "Retrieve unresolved call sites, dynamic dispatches, missing edges, and coverage limitations. "
            "Use this to understand what the static graph could not prove."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="record_hypothesis",
        description=(
            "Record or update a vulnerability hypothesis with statement, entry point, target operation, "
            "preconditions, and initial supporting evidence."
        ),
        parameters={
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string", "description": "Unique identifier (e.g. 'hyp_auth_01')"},
                "target_symbol": {"type": "string", "description": "Vulnerable function, method, or sink symbol"},
                "entry_point": {"type": "string", "description": "Entry point path or trigger"},
                "sensitive_operation": {"type": "string", "description": "Sensitive operation impacted"},
                "statement": {"type": "string", "description": "Concise statement of the security hypothesis"},
                "preconditions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Preconditions required for exploitation",
                },
                "supporting_evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Initial observed evidence facts",
                },
            },
            "required": ["hypothesis_id", "target_symbol", "entry_point", "sensitive_operation", "statement"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="challenge_hypothesis",
        description=(
            "Challenge or critique an existing hypothesis by recording observed counterevidence, "
            "sanitizers, or guards, updating its disposition to 'open', 'confirmed', 'mitigated', or 'false_positive'."
        ),
        parameters={
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string", "description": "ID of hypothesis to challenge"},
                "counterevidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Observed mitigating controls, guards, or sanitizers",
                },
                "disposition": {
                    "type": "string",
                    "enum": ["open", "confirmed", "mitigated", "false_positive"],
                    "description": "Updated disposition of the hypothesis",
                },
                "explanation": {"type": "string", "description": "Rationale for disposition update"},
            },
            "required": ["hypothesis_id", "disposition"],
            "additionalProperties": False,
        },
    ),
    ToolDefinition(
        name="finish_investigation",
        description=(
            "Conclude the investigation and submit discovered vulnerability findings. "
            "All findings will be strictly verified against repository source code citations."
        ),
        parameters={
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "High-level summary of investigation results"},
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string", "description": "Clear vulnerability title"},
                            "rule_id": {"type": "string", "description": "Rule identifier or 'AI-DISCOVERY-...'"},
                            "file_path": {"type": "string", "description": "File path where flaw exists"},
                            "start_line": {"type": "integer", "description": "Starting line number"},
                            "end_line": {"type": "integer", "description": "Ending line number"},
                            "summary": {"type": "string", "description": "Detailed explanation of flaw and impact"},
                            "category": {"type": "string", "description": "Vulnerability category"},
                            "severity": {
                                "type": "string",
                                "enum": ["critical", "high", "medium", "low", "informational"],
                            },
                            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                            "entry_point": {"type": "string", "description": "Attacker entry point"},
                            "prerequisites": {"type": "array", "items": {"type": "string"}},
                            "supporting_evidence": {"type": "array", "items": {"type": "string"}},
                            "counterevidence": {"type": "array", "items": {"type": "string"}},
                            "attack_chain_steps": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Ordered steps required to exploit vulnerability",
                            },
                        },
                        "required": ["title", "file_path", "start_line", "end_line", "summary", "category", "severity"],
                    },
                    "description": "List of discovered vulnerability findings",
                },
            },
            "required": ["summary", "findings"],
            "additionalProperties": False,
        },
    ),
]


class InvestigationToolExecutor:
    """Executes structured investigation tool calls against repository analysis state."""

    def __init__(
        self,
        repository_root: Path | str,
        intelligence: RepositoryIntelligence,
        graph: SemanticProgramGraph,
        storage: SQLiteStorage | None = None,
        source_revision: str = "",
    ) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self.intelligence = intelligence
        self.graph = graph
        self.storage = storage
        self.source_revision = source_revision
        self.hypotheses: dict[str, InvestigationHypothesis] = {}
        self.findings: list[Finding] = []
        self.invalid_citations: list[dict[str, Any]] = []
        self.is_finished: bool = False
        self.finish_summary: str = ""

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch and execute a tool call with robust error containment."""
        try:
            handler = getattr(self, f"_tool_{tool_name}", None)
            if not handler:
                return {
                    "status": "error",
                    "error": f"Unknown tool: '{tool_name}'. Available tools: {[t.name for t in INVESTIGATION_TOOLS]}",
                }
            return handler(arguments)  # type: ignore[no-any-return]
        except Exception as err:
            logger.exception("Error executing tool %s with args %s: %s", tool_name, arguments, err)
            return {
                "status": "error",
                "tool": tool_name,
                "error": f"Tool execution failed: {type(err).__name__}: {err}",
            }

    def _tool_get_repository_overview(self, _args: dict[str, Any]) -> dict[str, Any]:
        routes = self.graph.find_nodes(kind=NodeKind.ROUTE)
        sensitive_sinks = [
            n for n in self.graph.nodes.values()
            if n.kind in (
                NodeKind.SENSITIVE_SINK,
                NodeKind.QUERY,
                NodeKind.PROCESS_EXEC,
                NodeKind.EXTERNAL_REQUEST,
                NodeKind.FILE_OPERATION,
            )
        ]
        unresolved = self.graph.find_unresolved_regions()

        repo_files = sorted([f.replace("\\", "/") for f in self.intelligence.file_metadata])
        if not repo_files:
            for p in self.repository_root.rglob("*.py"):
                if p.is_file() and not any(part.startswith(".") or part in ("__pycache__", "node_modules", "venv") for part in p.parts):
                    with contextlib.suppress(Exception):
                        repo_files.append(str(p.relative_to(self.repository_root)).replace("\\", "/"))
            repo_files.sort()

        entry_points: list[dict[str, Any]] = []
        for fpath, syms in self.intelligence.symbols.items():
            norm_f = fpath.replace("\\", "/")
            for s in syms:
                if s.kind in ("function", "method", "class") and (
                    any(k in norm_f for k in ("api", "router", "route", "service", "handler", "worker")) or s.decorators
                ):
                    entry_points.append({
                        "name": s.name,
                        "qualified_name": s.qualified_name,
                        "kind": s.kind,
                        "file_path": norm_f,
                        "line": s.start_line,
                        "decorators": s.decorators,
                    })

        return {
            "status": "success",
            "repository_root": str(self.repository_root),
            "source_revision": self.source_revision,
            "total_nodes": len(self.graph.nodes),
            "total_routes": len(routes),
            "total_sensitive_sinks": len(sensitive_sinks),
            "unresolved_dispatch_areas": len(unresolved),
            "repository_files": repo_files,
            "key_entry_points": entry_points[:25],
            "routes": [
                {
                    "route_path": r.properties.get("route_path", r.label),
                    "handler": r.properties.get("handler", r.label),
                    "file_path": r.file_path,
                    "line": r.start_line,
                }
                for r in routes[:25]
            ],
            "sensitive_sinks_sample": [
                {
                    "kind": s.kind.value,
                    "symbol": s.label,
                    "file_path": s.file_path,
                    "line": s.start_line,
                }
                for s in sensitive_sinks[:15]
            ],
            "auth_boundaries_count": len(self.intelligence.auth_boundaries),
            "unresolved_sample": unresolved[:5],
        }

    def _tool_list_repository_files(self, args: dict[str, Any]) -> dict[str, Any]:
        target_dir = args.get("directory", "").strip().strip("/\\").replace("\\", "/")
        repo_files = sorted([f.replace("\\", "/") for f in self.intelligence.file_metadata])
        if not repo_files:
            for p in self.repository_root.rglob("*"):
                if p.is_file() and not any(part.startswith(".") or part in ("__pycache__", "node_modules", "venv") for part in p.parts):
                    with contextlib.suppress(Exception):
                        repo_files.append(str(p.relative_to(self.repository_root)).replace("\\", "/"))
            repo_files.sort()

        if target_dir:
            filtered = [f for f in repo_files if f.startswith(target_dir + "/") or f == target_dir]
        else:
            filtered = repo_files

        return {
            "status": "success",
            "directory": target_dir or "/",
            "total_files": len(filtered),
            "files": filtered[:100],
        }

    def _tool_get_source_excerpt(self, args: dict[str, Any]) -> dict[str, Any]:
        raw_file_path = args.get("file_path", "").strip()
        file_path = raw_file_path.replace("\\", "/")
        repo_str = str(self.repository_root).replace("\\", "/")
        if file_path.startswith(repo_str):
            file_path = file_path[len(repo_str):].lstrip("/\\")
        if file_path.startswith("./"):
            file_path = file_path[2:]
        file_path = file_path.lstrip("/")

        symbol = args.get("symbol", "").strip()

        start_line_arg = args.get("start_line")
        end_line_arg = args.get("end_line")

        # If symbol provided without explicit start_line, auto-locate symbol lines
        if symbol and (start_line_arg is None or (int(start_line_arg) == 1 and end_line_arg is None)):
            resolved_start, resolved_end = None, None
            for fpath, syms in self.intelligence.symbols.items():
                if not file_path or file_path in fpath:
                    for s in syms:
                        if s.name.lower() == symbol.lower() or s.qualified_name.lower().endswith(symbol.lower()):
                            file_path = fpath
                            resolved_start = s.start_line
                            resolved_end = s.end_line
                            break
                    if resolved_start is not None:
                        break
            if resolved_start is None:
                for node in self.graph.nodes.values():
                    if (not file_path or (node.file_path and file_path in node.file_path)) and (
                        node.label.lower() == symbol.lower() or symbol.lower() in node.id.lower()
                    ):
                        if node.file_path:
                            file_path = node.file_path
                        resolved_start = node.start_line
                        resolved_end = node.end_line
                        break
            if resolved_start is not None:
                start_line = resolved_start
                end_line = resolved_end or (resolved_start + 45)
            else:
                start_line = max(1, int(start_line_arg or 1))
                end_line = max(start_line, int(end_line_arg or start_line + 45))
        else:
            start_line = max(1, int(start_line_arg or 1))
            end_line = max(start_line, int(end_line_arg or start_line))

        max_lines = min(100, max(1, int(args.get("max_lines", 50))))

        try:
            full_path = resolve_safe_path(self.repository_root, file_path)
            if not full_path.is_file():
                return {"status": "error", "error": f"File '{file_path}' does not exist in repository."}

            content = full_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            total_lines = len(lines)

            clamped_start = min(start_line, total_lines)
            clamped_end = min(end_line, clamped_start + max_lines - 1, total_lines)

            snippet_lines = []
            for lineno in range(clamped_start, clamped_end + 1):
                idx = lineno - 1
                snippet_lines.append(f"{lineno:4d} | {lines[idx]}")

            return {
                "status": "success",
                "file_path": file_path.replace("\\", "/"),
                "start_line": clamped_start,
                "end_line": clamped_end,
                "total_lines": total_lines,
                "is_truncated": (end_line > clamped_end),
                "snippet": "\n".join(snippet_lines),
            }
        except Exception as err:
            return {"status": "error", "error": f"Failed to retrieve excerpt: {err}"}

    def _tool_query_symbols(self, args: dict[str, Any]) -> dict[str, Any]:
        raw_query = args.get("query", "").strip()
        query = raw_query.lower()
        scope_file = args.get("file_path", "").strip().replace("\\", "/")
        repo_str = str(self.repository_root).replace("\\", "/")
        if scope_file.startswith(repo_str):
            scope_file = scope_file[len(repo_str):].lstrip("/\\")
        if scope_file.startswith("./"):
            scope_file = scope_file[2:]
        scope_file = scope_file.lstrip("/")

        matches: list[dict[str, Any]] = []

        is_all_query = query in ("", "*", "all")
        is_func_query = query in ("def", "function", "func", "async_function", "method")
        is_class_query = query in ("class", "classes")

        # 1. Search intelligence symbols
        for fpath, sym_list in self.intelligence.symbols.items():
            norm_f = fpath.replace("\\", "/")
            if scope_file and scope_file not in norm_f:
                continue
            for s in sym_list:
                match = False
                if is_all_query or is_func_query and s.kind in ("function", "async_function", "method") or is_class_query and s.kind == "class" or query in s.name.lower() or query in s.qualified_name.lower():
                    match = True

                if match:
                    matches.append({
                        "name": s.name,
                        "qualified_name": s.qualified_name,
                        "kind": s.kind,
                        "file_path": norm_f,
                        "start_line": s.start_line,
                        "end_line": s.end_line,
                    })

        # 2. Search SPG nodes
        for node in self.graph.nodes.values():
            node_fpath = (node.file_path or "").replace("\\", "/")
            if scope_file and node_fpath and scope_file not in node_fpath:
                continue
            match = False
            if is_all_query or is_func_query and node.kind in (NodeKind.FUNCTION, NodeKind.METHOD) or is_class_query and node.kind == NodeKind.CLASS or query in node.label.lower() or query in node.id.lower():
                match = True

            if match and not any(
                m["file_path"] == node_fpath and m["start_line"] == node.start_line for m in matches
            ):
                matches.append({
                    "name": node.label,
                    "qualified_name": node.id,
                    "kind": node.kind.value,
                    "file_path": node_fpath,
                    "start_line": node.start_line,
                    "end_line": node.end_line,
                })

        return {
            "status": "success",
            "query": raw_query,
            "total_matches": len(matches),
            "matches": matches[:50],
        }

    def _tool_query_callers_callees(self, args: dict[str, Any]) -> dict[str, Any]:
        symbol = args.get("symbol", "")
        direction = args.get("direction", "both")

        callers: list[dict[str, Any]] = []
        callees: list[dict[str, Any]] = []

        # Find matching nodes
        matching_nodes = [
            n for n in self.graph.nodes.values()
            if symbol.lower() == n.label.lower() or symbol.lower() in n.id.lower()
        ]

        for node in matching_nodes:
            # Callers (in edges with CALLS)
            if direction in ("callers", "both"):
                for in_edge in self.graph.in_edges.get(node.id, []):
                    if in_edge.kind in (EdgeKind.CALLS, EdgeKind.DEFINES, EdgeKind.REACHES):
                        src_node = self.graph.nodes.get(in_edge.source_id)
                        callers.append({
                            "caller_id": in_edge.source_id,
                            "caller_label": src_node.label if src_node else in_edge.source_id,
                            "file_path": src_node.file_path if src_node else "",
                            "line": src_node.start_line if src_node else 0,
                            "edge_kind": in_edge.kind.value,
                        })

            # Callees (out edges with CALLS)
            if direction in ("callees", "both"):
                for out_edge in self.graph.out_edges.get(node.id, []):
                    if out_edge.kind in (EdgeKind.CALLS, EdgeKind.DEFINES, EdgeKind.REACHES):
                        tgt_node = self.graph.nodes.get(out_edge.target_id)
                        callees.append({
                            "callee_id": out_edge.target_id,
                            "callee_label": tgt_node.label if tgt_node else out_edge.target_id,
                            "file_path": tgt_node.file_path if tgt_node else "",
                            "line": tgt_node.start_line if tgt_node else 0,
                            "edge_kind": out_edge.kind.value,
                        })

        # Also cross-check call graph in intelligence
        for edge in self.intelligence.call_graph:
            if edge.callee_name.lower() == symbol.lower() and direction in ("callers", "both"):
                if not any(c.get("caller_label") == edge.caller_symbol for c in callers):
                    callers.append({
                        "caller_id": edge.caller_symbol,
                        "caller_label": edge.caller_symbol,
                        "file_path": edge.caller_file,
                        "line": edge.line,
                        "edge_kind": "calls",
                    })
            elif (
                edge.caller_symbol.lower() == symbol.lower()
                and direction in ("callees", "both")
                and not any(c.get("callee_label") == edge.callee_name for c in callees)
            ):
                callees.append({
                    "callee_id": edge.callee_name,
                    "callee_label": edge.callee_name,
                    "file_path": edge.caller_file,
                    "line": edge.line,
                    "edge_kind": "calls",
                })

        return {
            "status": "success",
            "symbol": symbol,
            "callers_count": len(callers),
            "callees_count": len(callees),
            "callers": callers[:20],
            "callees": callees[:20],
        }

    def _tool_query_dataflow_path(self, args: dict[str, Any]) -> dict[str, Any]:
        src_sym = args.get("source_symbol", "")
        snk_sym = args.get("sink_symbol", "")

        # Search for paths in SPG
        src_nodes = [n for n in self.graph.nodes.values() if src_sym.lower() in n.label.lower()]
        snk_nodes = [n for n in self.graph.nodes.values() if snk_sym.lower() in n.label.lower()]

        if not src_nodes or not snk_nodes:
            return {
                "status": "inconclusive",
                "message": f"Could not anchor source '{src_sym}' or sink '{snk_sym}' in graph.",
                "note": "Absence of graph edge does NOT prove safety. Inspect source code excerpts directly.",
            }

        s_node = src_nodes[0]
        t_node = snk_nodes[0]
        paths = self.graph.find_paths(s_node.id, t_node.id, max_depth=6)

        return {
            "status": "success",
            "source": s_node.id,
            "sink": t_node.id,
            "paths_found": len(paths),
            "paths": [
                [
                    {
                        "node_id": nid,
                        "label": self.graph.nodes[nid].label if nid in self.graph.nodes else nid,
                        "file_path": self.graph.nodes[nid].file_path if nid in self.graph.nodes else "",
                        "line": self.graph.nodes[nid].start_line if nid in self.graph.nodes else 0,
                    }
                    for nid in p
                ]
                for p in paths[:3]
            ],
            "caveat": "Dynamic dispatch, reflection, or unindexed frameworks may permit propagation beyond static paths.",
        }

    def _tool_query_route_reachability(self, args: dict[str, Any]) -> dict[str, Any]:
        route_path = args.get("route_path", "")

        route_nodes = [
            n for n in self.graph.find_nodes(kind=NodeKind.ROUTE)
            if n.properties.get("route_path") == route_path or route_path.lower() in n.label.lower()
        ]

        if not route_nodes:
            return {
                "status": "error",
                "error": f"Route '{route_path}' not found in graph.",
                "available_routes": [
                    r.properties.get("route_path", r.label) for r in self.graph.find_nodes(kind=NodeKind.ROUTE)
                ],
            }

        r_node = route_nodes[0]
        boundary = self.graph.find_boundary_crossings(r_node.id)

        return {
            "status": "success",
            "route_path": r_node.properties.get("route_path", r_node.label),
            "handler": r_node.properties.get("handler", r_node.label),
            "file_path": r_node.file_path,
            "line": r_node.start_line,
            "is_authenticated": boundary.get("is_authenticated", False),
            "auth_decorators": boundary.get("auth_decorators", []),
            "queries_executed": boundary.get("queries_executed", []),
            "external_requests": boundary.get("external_requests", []),
            "process_executions": boundary.get("process_executions", []),
        }

    def _tool_query_authorization_boundary(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()

        # 1. Search intelligence auth boundaries (route-level)
        matching_boundary = None
        for b in self.intelligence.auth_boundaries:
            if target == b.route_path or target == b.handler_name or target in b.route_path:
                matching_boundary = b
                break

        # 2. Search symbols or graph nodes for function implementation
        target_fpath = matching_boundary.file_path if matching_boundary else None
        target_sline = matching_boundary.line if matching_boundary else None
        target_eline = None
        symbol_name = matching_boundary.handler_name if matching_boundary else target

        if not target_fpath:
            for fpath, syms in self.intelligence.symbols.items():
                for s in syms:
                    if target.lower() in s.name.lower() or target.lower() in s.qualified_name.lower():
                        target_fpath = fpath
                        target_sline = s.start_line
                        target_eline = s.end_line
                        symbol_name = s.name
                        break
                if target_fpath:
                    break

        if not target_fpath:
            for node in self.graph.nodes.values():
                if target.lower() in node.label.lower() or target.lower() in node.id.lower():
                    target_fpath = node.file_path
                    target_sline = node.start_line
                    target_eline = node.end_line
                    symbol_name = node.label
                    break

        # 3. Read function code if located to inspect inline authority & trust boundary semantics
        code_snippet = ""
        inline_auth_checks: list[str] = []
        trust_boundary_crossings: list[str] = []
        is_authenticated = bool(matching_boundary and matching_boundary.is_authenticated)
        auth_decorators = list(matching_boundary.auth_decorators) if matching_boundary else []

        if target_fpath and target_sline:
            try:
                full_p = resolve_safe_path(self.repository_root, target_fpath)
                if full_p.is_file():
                    lines = full_p.read_text(encoding="utf-8", errors="replace").splitlines()
                    # Include preceding lines to capture decorators
                    s_idx = max(0, target_sline - 6)
                    e_idx = min(len(lines), target_eline or (target_sline + 60))
                    code_snippet = "\n".join(lines[s_idx:e_idx])


                    lower_code = code_snippet.lower()

                    # Authentication keywords
                    authn_terms = ["@login_required", "@jwt_required", "authenticated", "current_user", "get_current_user", "verify_token", "jwt.decode"]
                    if any(k in lower_code for k in authn_terms):
                        is_authenticated = True

                    # Authorization / role / authority checks
                    auth_keywords = [
                        ("has_role", "Role check (has_role)"),
                        ("is_admin", "Admin role check (is_admin)"),
                        ("check_permission", "Permission verification (check_permission)"),
                        ("has_permission", "Permission check (has_permission)"),
                        ("verify_authority", "Caller authority verification"),
                        ("allowed_roles", "Allowed roles whitelist"),
                        ("scope in", "Scope inclusion check"),
                        ("caller_scope", "Caller scope verification"),
                        ("tenant_id ==", "Tenant isolation check"),
                        ("user_id ==", "User ownership verification"),
                        ("forbidden", "Explicit Forbidden denial"),
                    ]
                    for kw, desc in auth_keywords:
                        if kw in lower_code:
                            inline_auth_checks.append(desc)

                    # Trust boundary crossings (queues, background workers, signed tokens, delegation)
                    boundary_keywords = [
                        ("jwt.encode", "jwt.encode: Signs security/delegation token without downstream authority re-verification"),
                        ("issue_token", "Issues bearer/delegation token"),
                        ("delegation", "Crosses delegation boundary"),
                        ("queue.put", "Dispatches payload across asynchronous message queue"),
                        ("enqueue", "Enqueues asynchronous job without caller context re-validation"),
                        ("background_tasks", "Dispatches background worker task"),
                        ("celery", "Dispatches Celery worker task"),
                    ]
                    for bkw, bdesc in boundary_keywords:
                        if bkw in lower_code:
                            trust_boundary_crossings.append(bdesc)
            except Exception:
                pass

        if matching_boundary or target_fpath:
            is_admin_only = bool(matching_boundary and matching_boundary.is_admin_only) or "is_admin" in code_snippet
            is_tenant_scoped = bool(matching_boundary and matching_boundary.is_tenant_scoped) or "tenant_id" in code_snippet
            has_authorization = bool(inline_auth_checks or is_admin_only or (matching_boundary and matching_boundary.auth_decorators and any("role" in d.lower() or "admin" in d.lower() for d in matching_boundary.auth_decorators)))

            analysis_notes = []
            if is_authenticated and not has_authorization:
                analysis_notes.append(
                    "CRITICAL AUTH DIVERGENCE: Authentication is verified (caller identity established), "
                    "but AUTHORIZATION is unverified (caller authority over requested action/delegated scope is not enforced)."
                )
            elif not is_authenticated:
                analysis_notes.append("Endpoint/function is unauthenticated (publicly callable).")
            else:
                analysis_notes.append("Both authentication and authorization checks detected.")

            if trust_boundary_crossings:
                analysis_notes.append(
                    f"Trust boundaries crossed: {'; '.join(trust_boundary_crossings)}."
                )

            return {
                "status": "success",
                "target": target,
                "symbol_name": symbol_name,
                "file_path": target_fpath,
                "line": target_sline,
                "authentication_enforced": is_authenticated,
                "auth_decorators": auth_decorators,
                "authorization_enforced": has_authorization,
                "inline_authority_checks": inline_auth_checks,
                "is_admin_only": is_admin_only,
                "is_tenant_scoped": is_tenant_scoped,
                "trust_boundary_crossings": trust_boundary_crossings,
                "security_assessment": " ".join(analysis_notes),
            }

        return {
            "status": "unprotected_or_not_found",
            "target": target,
            "message": f"No explicit authorization boundary or symbol definition detected for '{target}'.",
            "note": "Target may be publicly exposed or dynamically dispatched.",
        }

    def _tool_query_alternate_entry_points(self, args: dict[str, Any]) -> dict[str, Any]:
        sink_symbol = args.get("sink_symbol", "")

        # Find matching sink nodes
        sink_nodes = [
            n for n in self.graph.nodes.values()
            if sink_symbol.lower() in n.label.lower() or sink_symbol.lower() in n.kind.value.lower()
        ]

        if not sink_nodes:
            return {"status": "error", "error": f"No sink node matching '{sink_symbol}' found."}

        target_sink = sink_nodes[0]
        alternates = self.graph.find_alternate_entry_points(target_sink.id)

        return {
            "status": "success",
            "target_sink": target_sink.label,
            "target_kind": target_sink.kind.value,
            "file_path": target_sink.file_path,
            "line": target_sink.start_line,
            "total_alternate_routes": len(alternates),
            "alternate_routes": alternates,
        }

    def _tool_get_analysis_gaps(self, _args: dict[str, Any]) -> dict[str, Any]:
        unresolved = self.graph.find_unresolved_regions()
        unresolved_calls = self.intelligence.unresolved_calls

        return {
            "status": "success",
            "total_unresolved_regions": len(unresolved),
            "total_unresolved_calls": len(unresolved_calls),
            "unresolved_regions_sample": unresolved[:10],
            "unresolved_calls_sample": [
                {
                    "call_expression": u.call_expression,
                    "file_path": u.file_path,
                    "line": u.line,
                    "reason": u.reason,
                }
                for u in unresolved_calls[:10]
            ],
            "security_guidance": (
                "CRITICAL: Unresolved calls or absent graph edges must NEVER be treated as proof of safety. "
                "Always verify whether attacker-controlled input can reach these unresolved call sites."
            ),
        }

    def _tool_record_hypothesis(self, args: dict[str, Any]) -> dict[str, Any]:
        hyp_id = args.get("hypothesis_id", "")
        hyp = InvestigationHypothesis(
            hypothesis_id=hyp_id,
            rule_id="AI-DISCOVERY-" + hyp_id.upper()[:12],
            target_symbol=args.get("target_symbol", ""),
            entry_point=args.get("entry_point", ""),
            sensitive_operation=args.get("sensitive_operation", ""),
            statement=args.get("statement", ""),
            preconditions=list(args.get("preconditions", [])),
            supporting_evidence=list(args.get("supporting_evidence", [])),
            disposition="open",
        )
        self.hypotheses[hyp_id] = hyp

        return {
            "status": "success",
            "hypothesis_id": hyp_id,
            "disposition": "open",
            "message": f"Hypothesis '{hyp_id}' recorded for investigation.",
        }

    def _tool_challenge_hypothesis(self, args: dict[str, Any]) -> dict[str, Any]:
        hyp_id = args.get("hypothesis_id", "")
        if hyp_id not in self.hypotheses:
            return {"status": "error", "error": f"Hypothesis '{hyp_id}' not found. Record it first."}

        hyp = self.hypotheses[hyp_id]
        counter = args.get("counterevidence", [])
        disposition = args.get("disposition", hyp.disposition)
        explanation = args.get("explanation", "")

        hyp.counterevidence.extend(counter)
        hyp.disposition = disposition
        hyp.uncertainty = explanation

        return {
            "status": "success",
            "hypothesis_id": hyp_id,
            "updated_disposition": disposition,
            "counterevidence_count": len(hyp.counterevidence),
            "message": f"Hypothesis '{hyp_id}' updated to '{disposition}'.",
        }

    def _tool_finish_investigation(self, args: dict[str, Any]) -> dict[str, Any]:
        summary = args.get("summary", "")
        raw_findings = args.get("findings", [])
        if isinstance(raw_findings, str):
            try:
                raw_findings = json.loads(raw_findings)
            except Exception:
                raw_findings = []
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings] if isinstance(raw_findings, dict) else []

        self.is_finished = True
        self.finish_summary = summary
        self.findings = []

        validated_count = 0
        invalid_citations: list[dict[str, Any]] = []

        for rf in raw_findings:
            if isinstance(rf, str):
                try:
                    rf = json.loads(rf)
                except Exception:
                    continue
            if not isinstance(rf, dict):
                continue

            raw_fpath = rf.get("file_path", "").strip().replace("\\", "/")
            repo_str = str(self.repository_root).replace("\\", "/").rstrip("/")
            if raw_fpath.startswith(repo_str):
                raw_fpath = raw_fpath[len(repo_str):]
            if raw_fpath.startswith("./"):
                raw_fpath = raw_fpath[2:]
            fpath = raw_fpath.lstrip("/")

            # Retrieve snippet from file and clamp line numbers to actual line count
            try:
                full_p = resolve_safe_path(self.repository_root, fpath)
                lines = full_p.read_text(encoding="utf-8", errors="replace").splitlines()
                total_lines = len(lines)
                sline = max(1, min(int(rf.get("start_line", 1)), total_lines))
                eline = max(sline, min(int(rf.get("end_line", sline)), total_lines))
                s_idx = max(0, sline - 1)
                e_idx = min(len(lines), eline)
                snippet = "\n".join(lines[s_idx:e_idx])
            except Exception:
                sline = int(rf.get("start_line", 1))
                eline = int(rf.get("end_line", sline))
                snippet = ""

            loc = SourceLocation(
                file_path=fpath.replace("\\", "/"),
                start_line=sline,
                end_line=eline,
                symbol=rf.get("entry_point", rf.get("title", "")),
                role="sink",
            )
            evidence = CodeEvidence(
                snippet=snippet,
                start_line=sline,
                end_line=eline,
                explanation=rf.get("summary", ""),
                role="sink",
            )

            # Map category
            cat_str = rf.get("category", "generic").lower()
            cat = VulnerabilityCategory.GENERIC
            for c in VulnerabilityCategory:
                if c.value in cat_str or cat_str in c.value:
                    cat = c
                    break

            # Map severity
            sev_str = rf.get("severity", "high").lower()
            sev = SeverityLevel.HIGH
            for s in SeverityLevel:
                if s.value == sev_str:
                    sev = s
                    break

            # Build attack chain
            steps: list[AttackChainStep] = []
            raw_steps = rf.get("attack_chain_steps", [])
            for idx, step_item in enumerate(raw_steps, start=1):
                if isinstance(step_item, dict):
                    step_desc = str(step_item.get("description", step_item.get("action", str(step_item))))
                    step_op = str(step_item.get("operation_type", "attack_step"))
                else:
                    step_desc = str(step_item)
                    step_op = "attack_step"
                steps.append(
                    AttackChainStep(
                        step_number=idx,
                        location=loc,
                        operation_type=step_op,
                        description=step_desc,
                    )
                )

            achain = AttackChain(
                chain_id=f"achain_{rf.get('rule_id', 'ai').lower()}_{sline}",
                title=f"Attack Chain: {rf.get('title')}",
                starting_point=rf.get("entry_point", fpath),
                target_operation=rf.get("title", ""),
                steps=steps,
                potential_impact=rf.get("summary", ""),
            )

            f = Finding(
                finding_id=f"sqf_{rf.get('rule_id', 'ai').lower()}_{sline}",
                occurrence_id=f"occ_{rf.get('rule_id', 'ai').lower()}_{sline}",
                rule_id=rf.get("rule_id", "AI-DISCOVERY-001"),
                title=rf.get("title", "Discovered Vulnerability"),
                summary=rf.get("summary", ""),
                category=cat,
                severity=sev,
                confidence=ConfidenceLevel.HIGH if not rf.get("counterevidence") else ConfidenceLevel.MEDIUM,
                file_path=loc.file_path,
                start_line=sline,
                end_line=eline,
                locations=[loc],
                code_evidence=[evidence],
                data_flow=[DataFlowStep(location=loc, description=rf.get("summary", ""))],
                impact=rf.get("summary", ""),
                prerequisites=list(rf.get("prerequisites", [])),
                supporting_evidence=list(rf.get("supporting_evidence", [])),
                counterevidence=list(rf.get("counterevidence", [])),
                attack_chain=[str(s) for s in raw_steps],
                structured_attack_chain=achain,
                validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
                discovery_backend="ai_live_investigator",
            )
            f.fingerprint = f.calculate_fingerprint()

            # Verify local citations
            valid, reason = verify_finding_citations(self.repository_root, f)
            if valid:
                validated_count += 1
                self.findings.append(f)
            else:
                invalid_citations.append({"finding_id": f.finding_id, "title": f.title, "reason": reason})

        self.invalid_citations = invalid_citations

        return {
            "status": "success",
            "findings_submitted": len(raw_findings),
            "findings_validated": validated_count,
            "invalid_citations": invalid_citations,
            "message": f"Investigation finalized. {validated_count} verified finding(s) accepted.",
        }
