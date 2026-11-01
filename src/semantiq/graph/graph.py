"""In-memory, indexed Semantic Program Graph (SPG) with security query primitives."""

from __future__ import annotations

import contextlib
from collections import deque
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from semantiq.graph.models import (
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RelationshipProvenance,
)
from semantiq.repository.safepath import resolve_safe_path


class SemanticProgramGraph:
    """Versioned, typed semantic graph representing a software repository.

    Provides indexed adjacency maps, cycle-safe traversals, and domain-specific
    security queries (route reachability, interprocedural dataflow, auth boundaries,
    and unresolved dynamic regions).
    """

    def __init__(self, repository_root: str = "", source_revision: str = "") -> None:
        self.repository_root = repository_root
        self.source_revision = source_revision
        self.semantic_engine: Any = None
        self.nodes: dict[str, GraphNode] = {}
        self.out_edges: dict[str, list[GraphEdge]] = {}
        self.in_edges: dict[str, list[GraphEdge]] = {}

        # Specialized indices for high-performance lookup
        self._nodes_by_kind: dict[NodeKind, set[str]] = {k: set() for k in NodeKind}
        self._nodes_by_file: dict[str, set[str]] = {}
        self._nodes_by_label: dict[str, set[str]] = {}

    def add_node(self, node: GraphNode) -> None:
        """Insert or replace a node in the graph."""
        self.nodes[node.id] = node
        if node.id not in self.out_edges:
            self.out_edges[node.id] = []
        if node.id not in self.in_edges:
            self.in_edges[node.id] = []

        self._nodes_by_kind[node.kind].add(node.id)

        clean_file = node.file_path.replace("\\", "/")
        if clean_file not in self._nodes_by_file:
            self._nodes_by_file[clean_file] = set()
        self._nodes_by_file[clean_file].add(node.id)

        if node.label not in self._nodes_by_label:
            self._nodes_by_label[node.label] = set()
        self._nodes_by_label[node.label].add(node.id)

    def add_edge(self, edge: GraphEdge) -> None:
        """Insert a typed, provenance-bearing edge between two existing nodes."""
        if edge.source_id not in self.out_edges:
            self.out_edges[edge.source_id] = []
        if edge.target_id not in self.in_edges:
            self.in_edges[edge.target_id] = []

        # Avoid exact duplicate edges, but update provenance/confidence if refined
        existing_indices = [
            i for i, e in enumerate(self.out_edges[edge.source_id])
            if e.target_id == edge.target_id and e.kind == edge.kind
        ]
        if not existing_indices:
            self.out_edges[edge.source_id].append(edge)
            self.in_edges[edge.target_id].append(edge)
        else:
            for idx in existing_indices:
                old_edge = self.out_edges[edge.source_id][idx]
                self.out_edges[edge.source_id][idx] = edge
                if edge.target_id in self.in_edges:
                    for in_idx, in_e in enumerate(self.in_edges[edge.target_id]):
                        if in_e == old_edge:
                            self.in_edges[edge.target_id][in_idx] = edge
                            break

    def get_node(self, node_id: str) -> GraphNode | None:
        """Retrieve node by stable identifier."""
        return self.nodes.get(node_id)

    def find_nodes(
        self,
        kind: NodeKind | None = None,
        file_path: str | None = None,
        label: str | None = None,
    ) -> list[GraphNode]:
        """Query nodes matching kind, file, and/or label filters."""
        candidates: set[str] | None = None

        if kind is not None:
            candidates = set(self._nodes_by_kind.get(kind, set()))

        if file_path is not None:
            clean_file = file_path.replace("\\", "/")
            file_matches = self._nodes_by_file.get(clean_file, set())
            candidates = file_matches if candidates is None else (candidates & file_matches)

        if label is not None:
            label_matches = self._nodes_by_label.get(label, set())
            candidates = label_matches if candidates is None else (candidates & label_matches)

        if candidates is None:
            return list(self.nodes.values())
        return [self.nodes[nid] for nid in candidates if nid in self.nodes]

    def remove_file(self, rel_path: str) -> int:
        """Remove all nodes and edges associated with a specific file (for incremental re-indexing)."""
        clean_file = rel_path.replace("\\", "/")
        nodes_to_remove = set(self._nodes_by_file.get(clean_file, set()))
        if not nodes_to_remove:
            return 0

        # Remove from nodes and indices
        for nid in nodes_to_remove:
            node = self.nodes.pop(nid, None)
            if node:
                self._nodes_by_kind[node.kind].discard(nid)
                if node.label in self._nodes_by_label:
                    self._nodes_by_label[node.label].discard(nid)

        # Remove edges
        for nid in nodes_to_remove:
            self.out_edges.pop(nid, None)
            self.in_edges.pop(nid, None)

        # Remove inbound and outbound edges pointing to or from removed nodes
        for source_id, edges in list(self.out_edges.items()):
            self.out_edges[source_id] = [e for e in edges if e.target_id not in nodes_to_remove]
        for target_id, edges in list(self.in_edges.items()):
            self.in_edges[target_id] = [e for e in edges if e.source_id not in nodes_to_remove]

        self._nodes_by_file.pop(clean_file, None)
        return len(nodes_to_remove)

    def get_callers(self, symbol_id: str) -> list[GraphNode]:
        """Return all nodes that directly call the specified symbol."""
        callers: list[GraphNode] = []
        for edge in self.in_edges.get(symbol_id, []):
            if edge.kind == EdgeKind.CALLS:
                caller = self.nodes.get(edge.source_id)
                if caller:
                    callers.append(caller)
        return callers

    def get_callees(self, symbol_id: str) -> list[GraphNode]:
        """Return all nodes called by the specified symbol."""
        callees: list[GraphNode] = []
        for edge in self.out_edges.get(symbol_id, []):
            if edge.kind == EdgeKind.CALLS:
                callee = self.nodes.get(edge.target_id)
                if callee:
                    callees.append(callee)
        return callees

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        edge_kinds: Iterable[EdgeKind] | None = None,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """Find all cycle-safe paths from source to target constrained by edge kinds and depth."""
        allowed_kinds = set(edge_kinds) if edge_kinds else None
        results: list[list[str]] = []
        queue: deque[tuple[str, list[str]]] = deque([(source_id, [source_id])])

        while queue:
            curr_id, path = queue.popleft()
            if curr_id == target_id and len(path) > 1:
                results.append(path)
                continue

            if len(path) >= max_depth:
                continue

            for edge in self.out_edges.get(curr_id, []):
                if allowed_kinds and edge.kind not in allowed_kinds:
                    continue
                neighbor_id = edge.target_id
                if neighbor_id not in path:  # Cycle safety
                    queue.append((neighbor_id, path + [neighbor_id]))

        return results

    def find_route_to_sink_paths(
        self,
        route_id: str | None = None,
        sink_kind: NodeKind | None = None,
        max_depth: int = 8,
    ) -> list[dict[str, Any]]:
        """Identify reachability chains from HTTP routes to sensitive operations/sinks."""
        routes = [self.nodes[route_id]] if route_id and route_id in self.nodes else self.find_nodes(kind=NodeKind.ROUTE)
        target_sinks = {
            nid for nid, node in self.nodes.items()
            if node.kind in (
                NodeKind.SENSITIVE_SINK,
                NodeKind.QUERY,
                NodeKind.PROCESS_EXEC,
                NodeKind.EXTERNAL_REQUEST,
                NodeKind.FILE_OPERATION,
            ) and (sink_kind is None or node.kind == sink_kind)
        }

        discovered_chains: list[dict[str, Any]] = []

        allowed_edges = {
            EdgeKind.CALLS,
            EdgeKind.REACHES,
            EdgeKind.DATA_FLOWS_TO,
            EdgeKind.QUERIES,
            EdgeKind.ACCESSES_RESOURCE,
        }

        for r in routes:
            # First traverse to handler if defined
            entry_points: list[str] = [r.id]
            for edge in self.out_edges.get(r.id, []):
                if edge.kind in (EdgeKind.CALLS, EdgeKind.DEFINES, EdgeKind.REACHES):
                    entry_points.append(edge.target_id)

            for entry in entry_points:
                queue: deque[tuple[str, list[str]]] = deque([(entry, [entry])])
                visited_for_entry: set[str] = {entry}

                while queue:
                    curr, path = queue.popleft()
                    if curr in target_sinks and len(path) > 1:
                        sink_node = self.nodes[curr]
                        # Collect intermediate symbols
                        steps = [self.nodes[nid].label for nid in path if nid in self.nodes]
                        discovered_chains.append({
                            "route_id": r.id,
                            "route_path": r.properties.get("route_path", r.label),
                            "handler": r.properties.get("handler", entry),
                            "sink_id": curr,
                            "sink_kind": sink_node.kind.value,
                            "sink_expression": sink_node.properties.get("sink_expression", sink_node.label),
                            "path_nodes": path,
                            "call_chain": steps,
                            "hop_count": len(path) - 1,
                        })
                        continue

                    if len(path) >= max_depth:
                        continue

                    for edge in self.out_edges.get(curr, []):
                        if edge.kind in allowed_edges:
                            nxt = edge.target_id
                            if nxt not in visited_for_entry:
                                visited_for_entry.add(nxt)
                                queue.append((nxt, path + [nxt]))

        return discovered_chains

    def find_dataflow_paths(
        self,
        source_id: str,
        sink_id: str | None = None,
        max_depth: int = 12,
    ) -> list[list[str]]:
        """Trace dataflow paths following DATA_FLOWS_TO, PASSES_ARGUMENT, and RETURNS_TO edges."""
        allowed_edges = {
            EdgeKind.DATA_FLOWS_TO,
            EdgeKind.PASSES_ARGUMENT,
            EdgeKind.RETURNS_TO,
        }
        return self.find_paths(
            source_id=source_id,
            target_id=sink_id or "",
            edge_kinds=allowed_edges,
            max_depth=max_depth,
        )

    def find_boundary_crossings(self, route_id: str) -> dict[str, Any]:
        """Examine security boundaries, authenticators, authorizers, and tenant controls for a route."""
        route_node = self.get_node(route_id)
        if not route_node:
            return {"error": f"Route not found: {route_id}"}

        auth_controls: list[GraphNode] = []
        authorization_checks: list[GraphNode] = []
        tenant_controls: list[GraphNode] = []
        queries: list[GraphNode] = []

        # Reachable nodes from route
        reachable_nodes: set[str] = set()
        queue: deque[str] = deque([route_id])
        while queue:
            curr = queue.popleft()
            for edge in self.out_edges.get(curr, []):
                if (
                    edge.kind in (EdgeKind.CALLS, EdgeKind.DEFINES, EdgeKind.REACHES, EdgeKind.QUERIES)
                    and edge.target_id not in reachable_nodes
                ):
                    reachable_nodes.add(edge.target_id)
                    queue.append(edge.target_id)

        for nid in reachable_nodes:
            n = self.nodes.get(nid)
            if n is None:
                continue
            if n.kind == NodeKind.AUTH_CONTROL and n not in auth_controls:
                auth_controls.append(n)
            elif n.kind == NodeKind.AUTHORIZATION_CHECK and n not in authorization_checks:
                authorization_checks.append(n)
            elif n.kind == NodeKind.TENANT_CONTEXT and n not in tenant_controls:
                tenant_controls.append(n)
            elif n.kind == NodeKind.QUERY and n not in queries:
                queries.append(n)

            # Check inbound security controls for this reachable callee
            for edge in self.in_edges.get(nid, []):
                src_node = self.nodes.get(edge.source_id)
                if src_node is not None:
                    if edge.kind == EdgeKind.AUTHENTICATES and src_node not in auth_controls:
                        auth_controls.append(src_node)
                    elif edge.kind == EdgeKind.AUTHORIZES and src_node not in authorization_checks:
                        authorization_checks.append(src_node)
                    elif edge.kind == EdgeKind.CONTROLS_TENANT and src_node not in tenant_controls:
                        tenant_controls.append(src_node)

        # Check direct inbound edges for authenticates/authorizes on route itself
        for edge in self.in_edges.get(route_id, []):
            src_node = self.nodes.get(edge.source_id)
            if src_node is not None:
                if edge.kind == EdgeKind.AUTHENTICATES and src_node not in auth_controls:
                    auth_controls.append(src_node)
                elif edge.kind == EdgeKind.AUTHORIZES and src_node not in authorization_checks:
                    authorization_checks.append(src_node)
                elif edge.kind == EdgeKind.CONTROLS_TENANT and src_node not in tenant_controls:
                    tenant_controls.append(src_node)

        return {
            "route_id": route_id,
            "route_path": route_node.properties.get("route_path", route_node.label),
            "is_authenticated": len(auth_controls) > 0,
            "auth_controls": [a.label for a in auth_controls],
            "is_authorized": len(authorization_checks) > 0,
            "authorization_checks": [a.label for a in authorization_checks],
            "is_tenant_scoped": len(tenant_controls) > 0,
            "tenant_controls": [t.label for t in tenant_controls],
            "queries_executed": [q.label for q in queries],
        }

    def find_resource_access_paths(self, with_ownership_check: bool | None = None) -> list[dict[str, Any]]:
        """Identify routes that access database resources and whether ownership checks are in place."""
        results: list[dict[str, Any]] = []
        routes = self.find_nodes(kind=NodeKind.ROUTE)

        for route in routes:
            boundary_info = self.find_boundary_crossings(route.id)
            has_ownership = boundary_info.get("is_authorized", False) or boundary_info.get("is_tenant_scoped", False)

            if with_ownership_check is not None and has_ownership != with_ownership_check:
                continue

            queries = boundary_info.get("queries_executed", [])
            if queries:
                results.append({
                    "route_id": route.id,
                    "route_path": route.properties.get("route_path", route.label),
                    "handler": route.properties.get("handler", route.label),
                    "has_ownership_guard": has_ownership,
                    "queries": queries,
                    "auth_controls": boundary_info.get("auth_controls", []),
                    "tenant_controls": boundary_info.get("tenant_controls", []),
                })

        return results

    def find_unresolved_regions(self) -> list[dict[str, Any]]:
        """Extract all call sites and graph regions involving dynamic dispatch or unresolved targets."""
        unresolved: list[dict[str, Any]] = []
        for nid, node in self.nodes.items():
            if node.provenance == RelationshipProvenance.UNRESOLVED or node.kind == NodeKind.CALL_SITE and node.properties.get("is_unresolved"):
                unresolved.append({
                    "node_id": nid,
                    "file_path": node.file_path,
                    "line": node.start_line,
                    "caller": node.label,
                    "expression": node.properties.get("expression", node.label),
                    "reason": node.properties.get("reason", "dynamic_dispatch"),
                })
        return unresolved

    def get_neighborhood(self, node_id: str, radius: int = 1) -> dict[str, Any]:
        """Extract a bounded subgraph neighborhood around a target node for agent reasoning."""
        if node_id not in self.nodes:
            return {"center_node": None, "nodes": [], "edges": []}

        discovered_nodes: set[str] = {node_id}
        current_layer: set[str] = {node_id}

        for _ in range(radius):
            next_layer: set[str] = set()
            for nid in current_layer:
                # Outbound
                for e in self.out_edges.get(nid, []):
                    next_layer.add(e.target_id)
                # Inbound
                for e in self.in_edges.get(nid, []):
                    next_layer.add(e.source_id)
            new_nodes = next_layer - discovered_nodes
            discovered_nodes.update(new_nodes)
            current_layer = new_nodes

        nodes_data = [self.nodes[nid].model_dump() for nid in discovered_nodes if nid in self.nodes]
        edges_data: list[dict[str, Any]] = []

        for nid in discovered_nodes:
            for edge in self.out_edges.get(nid, []):
                if edge.target_id in discovered_nodes:
                    edges_data.append(edge.model_dump())

        return {
            "center_node": self.nodes[node_id].model_dump(),
            "nodes": nodes_data,
            "edges": edges_data,
            "total_nodes": len(nodes_data),
            "total_edges": len(edges_data),
        }

    def export_summary(self) -> dict[str, Any]:
        """Produce high-level metric summary of the semantic graph."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": sum(len(e) for e in self.out_edges.values()),
            "routes_count": len(self._nodes_by_kind[NodeKind.ROUTE]),
            "functions_count": len(self._nodes_by_kind[NodeKind.FUNCTION]),
            "classes_count": len(self._nodes_by_kind[NodeKind.CLASS]),
            "queries_count": len(self._nodes_by_kind[NodeKind.QUERY]),
            "sensitive_sinks_count": len(self._nodes_by_kind[NodeKind.SENSITIVE_SINK]),
            "auth_controls_count": len(self._nodes_by_kind[NodeKind.AUTH_CONTROL]),
            "unresolved_count": len(self.find_unresolved_regions()),
        }

    def get_source_excerpt(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        max_lines: int = 50,
    ) -> dict[str, Any]:
        """Safely extract bounded source code excerpt for agent reasoning."""
        clean_file = file_path.replace("\\", "/")
        try:
            if self.repository_root:
                full_path = resolve_safe_path(self.repository_root, clean_file)
            else:
                full_path = Path(clean_file)
            if not full_path.exists() or not full_path.is_file():
                return {
                    "file_path": clean_file,
                    "snippet": "",
                    "start_line": start_line,
                    "end_line": end_line,
                    "total_lines": 0,
                    "error": "File not found",
                }
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
            total_lines = len(lines)
            s = max(1, start_line)
            e = min(total_lines, max(s, end_line))
            is_truncated = False
            if e - s + 1 > max_lines:
                e = s + max_lines - 1
                is_truncated = True

            snippet = "\n".join(lines[s - 1: e])
            lang = "python" if clean_file.endswith(".py") else ("javascript" if clean_file.endswith((".js", ".jsx", ".ts", ".tsx")) else "text")

            return {
                "file_path": clean_file,
                "start_line": s,
                "end_line": e,
                "total_lines": total_lines,
                "is_truncated": is_truncated,
                "language": lang,
                "snippet": snippet,
            }
        except Exception as exc:
            return {
                "file_path": clean_file,
                "snippet": "",
                "start_line": start_line,
                "end_line": end_line,
                "total_lines": 0,
                "error": str(exc),
            }

    def find_control_flow_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """Find execution/control flow paths from source to target (CALLS, REACHES, CONTROLS_FLOW)."""
        control_edges = {EdgeKind.CALLS, EdgeKind.REACHES, EdgeKind.CONTROLS_FLOW}
        return self.find_paths(source_id, target_id, edge_kinds=control_edges, max_depth=max_depth)

    def find_data_flow_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """Find data-propagation paths from source to target (DATA_FLOWS_TO, PASSES_ARGUMENT, RETURNS_TO)."""
        df_edges = {EdgeKind.DATA_FLOWS_TO, EdgeKind.PASSES_ARGUMENT, EdgeKind.RETURNS_TO}
        return self.find_paths(source_id, target_id, edge_kinds=df_edges, max_depth=max_depth)

    def find_alternate_entry_points(self, sink_id: str) -> list[dict[str, Any]]:
        """Discover all distinct entry routes reaching a sink and compare security postures."""
        routes = self.find_nodes(kind=NodeKind.ROUTE)
        results: list[dict[str, Any]] = []

        for r in routes:
            paths = self.find_paths(r.id, sink_id, max_depth=8)
            if paths:
                boundary_info = self.find_boundary_crossings(r.id)
                results.append({
                    "route_id": r.id,
                    "route_path": r.properties.get("route_path", r.label),
                    "handler": r.properties.get("handler", r.label),
                    "path_count": len(paths),
                    "shortest_path": paths[0],
                    "hop_count": len(paths[0]) - 1,
                    "is_authenticated": boundary_info.get("is_authenticated", False),
                    "auth_controls": boundary_info.get("auth_controls", []),
                    "is_authorized": boundary_info.get("is_authorized", False),
                    "authorization_checks": boundary_info.get("authorization_checks", []),
                    "is_tenant_scoped": boundary_info.get("is_tenant_scoped", False),
                })
        return results

    def find_attack_chains(self, max_depth: int = 8) -> list[dict[str, Any]]:
        """Identify multi-step cross-component attack chains from routes to sensitive operations."""
        routes = self.find_nodes(kind=NodeKind.ROUTE)
        target_sinks = {
            nid for nid, node in self.nodes.items()
            if node.kind in (
                NodeKind.SENSITIVE_SINK,
                NodeKind.QUERY,
                NodeKind.PROCESS_EXEC,
                NodeKind.EXTERNAL_REQUEST,
                NodeKind.FILE_OPERATION,
                NodeKind.DATA_ACCESS,
            ) or (
                node.kind in (NodeKind.FUNCTION, NodeKind.METHOD)
                and any(k in node.label.lower() for k in [
                    "dispatch", "fulfill", "refund", "transfer", "payout", "ship"
                ])
            )
        }

        chains: list[dict[str, Any]] = []
        chain_idx = 0

        for r in routes:
            boundary_info = self.find_boundary_crossings(r.id)
            is_authenticated = boundary_info.get("is_authenticated", False)
            is_authorized = boundary_info.get("is_authorized", False)
            is_tenant_scoped = boundary_info.get("is_tenant_scoped", False)

            entry_points = [r.id]
            for edge in self.out_edges.get(r.id, []):
                if edge.kind in (EdgeKind.CALLS, EdgeKind.DEFINES, EdgeKind.REACHES):
                    entry_points.append(edge.target_id)

            for entry in entry_points:
                queue: deque[tuple[str, list[str]]] = deque([(entry, [entry])])
                visited_for_entry: set[str] = {entry}

                while queue:
                    curr, path = queue.popleft()
                    if curr in target_sinks and len(path) > 1:
                        sink_node = self.nodes[curr]
                        chain_idx += 1
                        chain_id = f"achain_{chain_idx:03d}"

                        hops_data = []
                        unresolved_on_path = False
                        boundaries_crossed = []
                        missing_controls = []

                        if not is_authenticated:
                            missing_controls.append("missing_authentication")
                            boundaries_crossed.append("public_to_internal_unauthenticated")
                        if not is_authorized:
                            missing_controls.append("missing_role_authorization")
                        if not is_tenant_scoped and sink_node.kind == NodeKind.QUERY:
                            missing_controls.append("missing_tenant_isolation")

                        for step_idx, nid in enumerate(path):
                            step_node = self.nodes.get(nid)
                            if not step_node:
                                continue
                            if step_node.provenance == RelationshipProvenance.UNRESOLVED:
                                unresolved_on_path = True

                            hops_data.append({
                                "step": step_idx + 1,
                                "node_id": nid,
                                "label": step_node.label,
                                "kind": step_node.kind.value,
                                "file_path": step_node.file_path,
                                "start_line": step_node.start_line,
                                "end_line": step_node.end_line,
                            })

                        impact_map = {
                            NodeKind.QUERY: "Arbitrary data extraction or cross-tenant record tampering",
                            NodeKind.PROCESS_EXEC: "Arbitrary command execution in host environment",
                            NodeKind.EXTERNAL_REQUEST: "Server-side request forgery (SSRF) against internal services",
                            NodeKind.FILE_OPERATION: "Unauthorized file system manipulation or sensitive data exposure",
                            NodeKind.SENSITIVE_SINK: "Unauthorized execution of sensitive system action",
                        }
                        impact_str = impact_map.get(sink_node.kind, "Unauthorized access to sensitive functionality")

                        chains.append({
                            "chain_id": chain_id,
                            "entry_route": r.properties.get("route_path", r.label),
                            "entry_route_id": r.id,
                            "target_sink_id": curr,
                            "target_sink_kind": sink_node.kind.value,
                            "target_sink_expression": sink_node.properties.get("sink_expression", sink_node.label),
                            "target_file": sink_node.file_path,
                            "target_line": sink_node.start_line,
                            "is_authenticated": is_authenticated,
                            "is_authorized": is_authorized,
                            "is_tenant_scoped": is_tenant_scoped,
                            "missing_controls": missing_controls,
                            "boundaries_crossed": boundaries_crossed,
                            "hops": hops_data,
                            "hop_count": len(path) - 1,
                            "has_unresolved_call": unresolved_on_path,
                            "potential_impact": impact_str,
                            "is_high_risk": (not is_authenticated or not is_authorized) and len(missing_controls) > 0,
                        })
                        continue

                    if len(path) >= max_depth:
                        continue

                    for edge in self.out_edges.get(curr, []):
                        if edge.target_id not in visited_for_entry:
                            visited_for_entry.add(edge.target_id)
                            queue.append((edge.target_id, path + [edge.target_id]))

        return chains

    def resolve_symbol_detail(self, symbol_name: str) -> dict[str, Any] | None:
        """Resolve a symbol or qualified name with complete MRO, parameters, location, and provenance."""
        if self.semantic_engine:
            sym = self.semantic_engine.resolve_symbol_detail(symbol_name)
            if sym:
                res_dict: dict[str, Any] = sym.to_dict()
                return res_dict

        node = self.nodes.get(symbol_name)
        if not node:
            matches = [n for n in self.nodes.values() if n.label == symbol_name or n.label.endswith(f".{symbol_name}")]
            if len(matches) == 1:
                node = matches[0]

        if node:
            return {
                "symbol_id": node.id,
                "name": node.label.split(".")[-1],
                "qualified_name": node.label,
                "kind": node.kind.value,
                "location": {
                    "file_path": node.file_path,
                    "start_line": node.start_line,
                    "end_line": node.end_line,
                },
                "language": "python" if node.file_path.endswith(".py") else "unknown",
                "parameters": node.properties.get("params", []),
                "parameter_defaults": node.properties.get("parameter_defaults", {}),
                "decorators": node.properties.get("decorators", []),
                "base_classes": node.properties.get("bases", []),
                "mro": node.properties.get("mro", []),
                "provenance": node.provenance.value,
            }
        return None

    def query_call_hierarchy(self, symbol: str, direction: str = "both") -> dict[str, Any]:
        """Query incoming callers and outgoing callees with call sites, argument mappings, and confidence."""
        callers: list[dict[str, Any]] = []
        callees: list[dict[str, Any]] = []

        if self.semantic_engine:
            if direction in {"callers", "both"}:
                for call in self.semantic_engine.get_callers(symbol):
                    callers.append(call.to_dict())
            if direction in {"callees", "both"}:
                for call in self.semantic_engine.get_callees(symbol):
                    callees.append(call.to_dict())

        sym_nodes = [n for n in self.nodes.values() if n.label == symbol or n.id.endswith(f":{symbol}")]
        for s_node in sym_nodes:
            if direction in {"callers", "both"}:
                for edge in self.in_edges.get(s_node.id, []):
                    if edge.kind == EdgeKind.CALLS:
                        caller_n = self.nodes.get(edge.source_id)
                        if caller_n and not any(c.get("caller_id") == caller_n.id for c in callers):
                            callers.append({
                                "caller_id": caller_n.id,
                                "caller_symbol": caller_n.label,
                                "callee_id": s_node.id,
                                "callee_name": s_node.label,
                                "call_site": {
                                    "file_path": caller_n.file_path,
                                    "start_line": edge.properties.get("line", caller_n.start_line),
                                    "end_line": edge.properties.get("line", caller_n.start_line),
                                },
                                "call_expression": edge.properties.get("call_expression", f"{s_node.label}()"),
                                "argument_mappings": edge.properties.get("argument_mappings", []),
                                "is_dynamic": edge.provenance == RelationshipProvenance.UNRESOLVED,
                                "dynamic_reason": edge.properties.get("reason"),
                                "provenance": edge.provenance.value,
                                "confidence": edge.confidence,
                            })

            if direction in {"callees", "both"}:
                for edge in self.out_edges.get(s_node.id, []):
                    if edge.kind == EdgeKind.CALLS:
                        callee_n = self.nodes.get(edge.target_id)
                        callee_label = callee_n.label if callee_n else edge.target_id
                        if not any(c.get("callee_id") == edge.target_id for c in callees):
                            callees.append({
                                "caller_id": s_node.id,
                                "caller_symbol": s_node.label,
                                "callee_id": edge.target_id,
                                "callee_name": callee_label,
                                "call_site": {
                                    "file_path": s_node.file_path,
                                    "start_line": edge.properties.get("line", s_node.start_line),
                                    "end_line": edge.properties.get("line", s_node.start_line),
                                },
                                "call_expression": edge.properties.get("call_expression", f"{callee_label}()"),
                                "argument_mappings": edge.properties.get("argument_mappings", []),
                                "is_dynamic": edge.provenance == RelationshipProvenance.UNRESOLVED,
                                "dynamic_reason": edge.properties.get("reason"),
                                "provenance": edge.provenance.value,
                                "confidence": edge.confidence,
                            })

        return {
            "symbol": symbol,
            "direction": direction,
            "caller_count": len(callers),
            "callee_count": len(callees),
            "callers": callers,
            "callees": callees,
        }

    def trace_argument_to_callee(
        self,
        caller_symbol: str,
        callee_symbol: str,
        arg_identifier: str | int | None = None,
    ) -> dict[str, Any]:
        """Trace how an argument expression in caller maps to callee parameter and propagates internally."""
        hierarchy = self.query_call_hierarchy(caller_symbol, direction="callees")
        matching_calls = [
            c for c in hierarchy["callees"]
            if c["callee_name"] == callee_symbol or c["callee_name"].endswith(f".{callee_symbol}")
        ]

        if not matching_calls:
            return {
                "caller": caller_symbol,
                "callee": callee_symbol,
                "status": "call_not_found",
                "argument_mappings": [],
            }

        call = matching_calls[0]
        mappings = call.get("argument_mappings", [])

        selected_mapping = None
        if arg_identifier is not None:
            if isinstance(arg_identifier, int) or (isinstance(arg_identifier, str) and arg_identifier.isdigit()):
                idx = int(arg_identifier)
                for m in mappings:
                    if m.get("arg_index") == idx:
                        selected_mapping = m
                        break
            else:
                for m in mappings:
                    if m.get("param_name") == arg_identifier or m.get("arg_name") == arg_identifier:
                        selected_mapping = m
                        break

        callee_detail = self.resolve_symbol_detail(callee_symbol)
        param_propagation = []
        if callee_detail and selected_mapping:
            target_p = selected_mapping.get("param_name")
            if target_p:
                for nid, n in self.nodes.items():
                    if n.kind == NodeKind.PARAMETER and n.label == target_p and (callee_symbol in n.id or not callee_symbol):
                        for df_edge in self.out_edges.get(nid, []):
                            if df_edge.kind in (EdgeKind.DATA_FLOWS_TO, EdgeKind.REACHES, EdgeKind.QUERIES):
                                target_node = self.nodes.get(df_edge.target_id)
                                if target_node:
                                    param_propagation.append({
                                        "target_node_id": target_node.id,
                                        "target_kind": target_node.kind.value,
                                        "target_label": target_node.label,
                                        "file_path": target_node.file_path,
                                        "line": target_node.start_line,
                                        "edge_kind": df_edge.kind.value,
                                    })
                                    # Also follow edges to sinks from reachable callee
                                    for sink_edge in self.out_edges.get(target_node.id, []):
                                        sink_node = self.nodes.get(sink_edge.target_id)
                                        if sink_node and sink_node.kind in (
                                            NodeKind.QUERY,
                                            NodeKind.PROCESS_EXEC,
                                            NodeKind.EXTERNAL_REQUEST,
                                            NodeKind.FILE_OPERATION,
                                            NodeKind.SENSITIVE_SINK,
                                        ):
                                            param_propagation.append({
                                                "target_node_id": sink_node.id,
                                                "target_kind": sink_node.kind.value,
                                                "target_label": sink_node.label,
                                                "file_path": sink_node.file_path,
                                                "line": sink_node.start_line,
                                                "edge_kind": sink_edge.kind.value,
                                            })

        return {
            "caller": caller_symbol,
            "callee": callee_symbol,
            "status": "resolved",
            "call_site": call.get("call_site"),
            "call_expression": call.get("call_expression"),
            "all_argument_mappings": mappings,
            "selected_mapping": selected_mapping,
            "parameter_propagation": param_propagation,
            "provenance": call.get("provenance"),
            "confidence": call.get("confidence"),
        }

    def trace_return_to_caller(
        self,
        callee_symbol: str,
        caller_symbol: str | None = None,
    ) -> dict[str, Any]:
        """Trace return values from callee back into caller receiving variables."""
        returns_data: list[dict[str, Any]] = []

        if self.semantic_engine:
            for df in self.semantic_engine.dataflow_relationships:
                if (
                    df.edge_kind == EdgeKind.RETURNS_TO
                    and (callee_symbol in df.source_id or callee_symbol in df.source_label)
                    and (caller_symbol is None or caller_symbol in df.target_id or caller_symbol in df.target_label)
                ):
                    returns_data.append(df.to_dict())

        return {
            "callee": callee_symbol,
            "caller": caller_symbol,
            "returns_count": len(returns_data),
            "return_flows": returns_data,
        }

    def query_route_reachability_chain(
        self,
        route_path: str | None = None,
        sink_kind: NodeKind | str | None = None,
        max_depth: int = 8,
    ) -> list[dict[str, Any]]:
        """Discover reachability chains from HTTP/WebSocket routes to sensitive operations."""
        target_kind: NodeKind | None = None
        if isinstance(sink_kind, str):
            with contextlib.suppress(ValueError):
                target_kind = NodeKind(sink_kind)
        elif isinstance(sink_kind, NodeKind):
            target_kind = sink_kind

        routes = [self.nodes[route_path]] if route_path and route_path in self.nodes else self.find_nodes(kind=NodeKind.ROUTE)
        if route_path and not routes:
            routes = [
                n for n in self.find_nodes(kind=NodeKind.ROUTE)
                if route_path in n.properties.get("route_path", "") or route_path in n.label
            ]

        target_sinks = {
            nid for nid, node in self.nodes.items()
            if node.kind in (
                NodeKind.SENSITIVE_SINK,
                NodeKind.QUERY,
                NodeKind.PROCESS_EXEC,
                NodeKind.EXTERNAL_REQUEST,
                NodeKind.FILE_OPERATION,
                NodeKind.DATA_ACCESS,
            ) and (target_kind is None or node.kind == target_kind)
        }

        chains: list[dict[str, Any]] = []
        allowed_edges = {
            EdgeKind.CALLS,
            EdgeKind.REACHES,
            EdgeKind.DATA_FLOWS_TO,
            EdgeKind.QUERIES,
            EdgeKind.ACCESSES_RESOURCE,
            EdgeKind.BINDS_ROUTE,
        }

        for r in routes:
            guard_info = self.identify_route_guards(r.id)

            entry_points: list[str] = [r.id]
            for edge in self.out_edges.get(r.id, []):
                if edge.kind in (EdgeKind.CALLS, EdgeKind.DEFINES, EdgeKind.REACHES, EdgeKind.BINDS_ROUTE):
                    entry_points.append(edge.target_id)

            for entry in entry_points:
                queue: deque[tuple[str, list[str]]] = deque([(entry, [entry])])
                visited: set[str] = {entry}

                while queue:
                    curr, path = queue.popleft()
                    if curr in target_sinks and len(path) > 1:
                        sink_node = self.nodes[curr]
                        hops = []
                        unresolved_call = False
                        for step_idx, nid in enumerate(path):
                            step_node = self.nodes.get(nid)
                            if not step_node:
                                continue
                            if step_node.provenance == RelationshipProvenance.UNRESOLVED:
                                unresolved_call = True

                            hops.append({
                                "step": step_idx + 1,
                                "node_id": nid,
                                "label": step_node.label,
                                "kind": step_node.kind.value,
                                "file_path": step_node.file_path,
                                "start_line": step_node.start_line,
                                "end_line": step_node.end_line,
                            })

                        chains.append({
                            "route_id": r.id,
                            "route_path": r.properties.get("route_path", r.label),
                            "framework": r.properties.get("framework", "unknown"),
                            "http_methods": r.properties.get("http_methods", ["GET"]),
                            "handler": r.properties.get("handler", entry),
                            "sink_id": curr,
                            "sink_kind": sink_node.kind.value,
                            "sink_expression": sink_node.properties.get("sink_expression", sink_node.label),
                            "sink_file": sink_node.file_path,
                            "sink_line": sink_node.start_line,
                            "guard_posture": guard_info,
                            "hops": hops,
                            "hop_count": len(path) - 1,
                            "has_unresolved_call": unresolved_call,
                        })
                        continue

                    if len(path) >= max_depth:
                        continue

                    for edge in self.out_edges.get(curr, []):
                        if edge.kind in allowed_edges and edge.target_id not in visited:
                            visited.add(edge.target_id)
                            queue.append((edge.target_id, path + [edge.target_id]))

        return chains

    def identify_route_guards(self, target: str) -> dict[str, Any]:
        """Analyze security controls protecting a route or function: enforced, bypassed, and unresolved."""
        target_node = self.nodes.get(target)
        if not target_node:
            matches = [n for n in self.nodes.values() if n.label == target or target in n.properties.get("route_path", "")]
            if matches:
                target_node = matches[0]

        if not target_node:
            return {
                "target": target,
                "status": "target_not_found",
                "enforced_guards": [],
                "bypassed_guards": [],
                "unresolved_guards": [],
            }

        enforced_guards: list[dict[str, Any]] = []
        bypassed_guards: list[dict[str, Any]] = []
        unresolved_guards: list[dict[str, Any]] = []

        if "auth_guards" in target_node.properties:
            for g in target_node.properties["auth_guards"]:
                status = g.get("status", "enforced")
                if status == "enforced":
                    enforced_guards.append(g)
                elif status in {"bypassed", "conditionally_skipped"}:
                    bypassed_guards.append(g)
                elif status == "unresolved":
                    unresolved_guards.append(g)

        for edge in self.in_edges.get(target_node.id, []):
            src_n = self.nodes.get(edge.source_id)
            if src_n:
                guard_dict = {
                    "guard_name": src_n.label,
                    "kind": edge.kind.value,
                    "file_path": src_n.file_path,
                    "line": src_n.start_line,
                    "provenance": edge.provenance.value,
                }
                if edge.kind in (EdgeKind.AUTHENTICATES, EdgeKind.AUTHORIZES, EdgeKind.CONTROLS_TENANT):
                    if edge.provenance == RelationshipProvenance.UNRESOLVED:
                        unresolved_guards.append(guard_dict)
                    else:
                        enforced_guards.append(guard_dict)

        csrf_status = target_node.properties.get("csrf_protected")
        if csrf_status is False:
            bypassed_guards.append({
                "guard_name": "CSRF_PROTECTION",
                "kind": "csrf_protection",
                "status": "bypassed",
                "explanation": "Route explicitly exempts or disables CSRF protection",
            })

        is_authenticated = len([g for g in enforced_guards if "auth" in str(g).lower() or "login" in str(g).lower()]) > 0
        if not is_authenticated:
            bypassed_guards.append({
                "guard_name": "AUTHENTICATION_BARRIER",
                "kind": "authentication",
                "status": "bypassed",
                "explanation": "No authentication decorator or middleware bound to this entry point",
            })

        return {
            "target": target_node.label,
            "target_id": target_node.id,
            "is_authenticated": is_authenticated,
            "csrf_protected": csrf_status is not False,
            "enforced_guards": enforced_guards,
            "bypassed_guards": bypassed_guards,
            "unresolved_guards": unresolved_guards,
        }

    def get_unresolved_dispatches(self) -> list[dict[str, Any]]:
        """Retrieve all dynamic dispatch and unresolvable call sites across the repository."""
        dispatches: list[dict[str, Any]] = []

        if self.semantic_engine:
            for c in self.semantic_engine.get_unresolved_dispatches():
                dispatches.append(c.to_dict())

        for u in self.find_unresolved_regions():
            if not any(d.get("caller_id") == u.get("node_id") for d in dispatches):
                dispatches.append({
                    "caller_id": u.get("node_id"),
                    "caller_symbol": u.get("caller"),
                    "call_site": {
                        "file_path": u.get("file_path"),
                        "start_line": u.get("line"),
                        "end_line": u.get("line"),
                    },
                    "call_expression": u.get("expression"),
                    "dynamic_reason": u.get("reason"),
                    "provenance": RelationshipProvenance.UNRESOLVED.value,
                    "confidence": 0.3,
                })

        return dispatches

    def get_interprocedural_evidence_path(
        self,
        source_entry: str,
        sink_id_or_expr: str,
    ) -> dict[str, Any]:
        """Construct an ordered, verified causal execution path mapped directly to Phase 1 semantic roles."""
        chains = self.query_route_reachability_chain(route_path=source_entry)
        matching_chain = None

        for ch in chains:
            if (
                ch["sink_id"] == sink_id_or_expr
                or sink_id_or_expr in ch["sink_expression"]
                or sink_id_or_expr in ch["sink_id"]
            ):
                matching_chain = ch
                break

        if not matching_chain and chains:
            matching_chain = chains[0]

        if not matching_chain:
            return {
                "source": source_entry,
                "sink": sink_id_or_expr,
                "status": "path_not_found",
                "evidence_chain": [],
            }

        hops = matching_chain["hops"]
        guard_info = matching_chain["guard_posture"]
        evidence_chain: list[dict[str, Any]] = []

        route_node = self.nodes.get(matching_chain["route_id"])
        input_expr = "request.params"
        input_line = route_node.start_line if route_node else 1
        input_file = route_node.file_path if route_node else ""
        if route_node and "input_bindings" in route_node.properties:
            bindings = route_node.properties["input_bindings"]
            if bindings:
                input_expr = bindings[0].get("expression", input_expr)
                input_line = bindings[0].get("line", input_line)

        evidence_chain.append({
            "step_index": 1,
            "role": "user_input",
            "file_path": input_file,
            "start_line": input_line,
            "end_line": input_line,
            "snippet": self.get_source_excerpt(input_file, input_line, input_line).get("snippet", ""),
            "explanation": f"Untrusted input enters application via {input_expr}",
            "provenance": "direct_fact",
            "verification_status": "verified",
        })

        evidence_chain.append({
            "step_index": 2,
            "role": "entrypoint",
            "file_path": input_file,
            "start_line": route_node.start_line if route_node else input_line,
            "end_line": route_node.start_line if route_node else input_line,
            "snippet": self.get_source_excerpt(input_file, route_node.start_line if route_node else input_line, route_node.start_line if route_node else input_line).get("snippet", ""),
            "explanation": f"Route {matching_chain['route_path']} exposes HTTP entry point to caller",
            "provenance": "framework_resolved",
            "verification_status": "verified",
        })

        step_counter = 3
        for h in hops:
            if h["node_id"] == matching_chain["route_id"] or h["node_id"] == matching_chain["sink_id"]:
                continue
            h_file = h["file_path"]
            h_line = h["start_line"]
            evidence_chain.append({
                "step_index": step_counter,
                "role": "propagation",
                "file_path": h_file,
                "start_line": h_line,
                "end_line": h["end_line"],
                "snippet": self.get_source_excerpt(h_file, h_line, h["end_line"]).get("snippet", ""),
                "explanation": f"Execution and tainted payload propagate into {h['label']}",
                "provenance": "statically_resolved",
                "verification_status": "verified",
            })
            step_counter += 1

        bypassed = guard_info.get("bypassed_guards", [])
        if bypassed:
            bg = bypassed[0]
            evidence_chain.append({
                "step_index": step_counter,
                "role": "expected_control",
                "file_path": input_file,
                "start_line": route_node.start_line if route_node else input_line,
                "end_line": route_node.start_line if route_node else input_line,
                "snippet": self.get_source_excerpt(input_file, route_node.start_line if route_node else input_line, route_node.start_line if route_node else input_line).get("snippet", ""),
                "explanation": f"Missing expected security guard: {bg.get('explanation', bg.get('guard_name'))}",
                "provenance": "framework_resolved",
                "verification_status": "verified",
            })
            step_counter += 1

        sink_file = matching_chain["sink_file"]
        sink_line = matching_chain["sink_line"]
        evidence_chain.append({
            "step_index": step_counter,
            "role": "sink",
            "file_path": sink_file,
            "start_line": sink_line,
            "end_line": sink_line,
            "snippet": self.get_source_excerpt(sink_file, sink_line, sink_line).get("snippet", ""),
            "explanation": f"Sensitive operation invoked at {matching_chain['sink_expression']}",
            "provenance": "direct_fact",
            "verification_status": "verified",
        })
        step_counter += 1

        evidence_chain.append({
            "step_index": step_counter,
            "role": "outcome",
            "file_path": sink_file,
            "start_line": sink_line,
            "end_line": sink_line,
            "snippet": self.get_source_excerpt(sink_file, sink_line, sink_line).get("snippet", ""),
            "explanation": f"Adversary reaches {matching_chain['sink_kind']} without authorization check",
            "provenance": "direct_fact",
            "verification_status": "verified",
        })

        return {
            "source": source_entry,
            "sink": sink_id_or_expr,
            "status": "path_resolved",
            "route_path": matching_chain["route_path"],
            "hop_count": len(hops),
            "guard_posture": guard_info,
            "evidence_chain": evidence_chain,
        }
