"""In-memory, indexed Semantic Program Graph (SPG) with security query primitives."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from typing import Any

from semantiq.graph.models import (
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RelationshipProvenance,
)


class SemanticProgramGraph:
    """Versioned, typed semantic graph representing a software repository.

    Provides indexed adjacency maps, cycle-safe traversals, and domain-specific
    security queries (route reachability, interprocedural dataflow, auth boundaries,
    and unresolved dynamic regions).
    """

    def __init__(self, repository_root: str = "", source_revision: str = "") -> None:
        self.repository_root = repository_root
        self.source_revision = source_revision
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
