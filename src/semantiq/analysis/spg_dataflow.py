"""Interprocedural data-flow analysis grounded in the Semantic Program Graph."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, GraphNode, NodeKind
from semantiq.models import DataFlowStep, SourceLocation, VulnerabilityCategory

# Vulnerability-to-sanitizer semantics mapping
SANITIZER_COMPATIBILITY: dict[str, set[VulnerabilityCategory]] = {
    "int": {VulnerabilityCategory.SQL_INJECTION, VulnerabilityCategory.COMMAND_INJECTION, VulnerabilityCategory.PATH_TRAVERSAL},
    "float": {VulnerabilityCategory.SQL_INJECTION, VulnerabilityCategory.COMMAND_INJECTION},
    "escape": {VulnerabilityCategory.CROSS_SITE_SCRIPTING},
    "quote": {VulnerabilityCategory.COMMAND_INJECTION},
    "validate_url": {VulnerabilityCategory.SSRF},
    "basename": {VulnerabilityCategory.PATH_TRAVERSAL, VulnerabilityCategory.INSECURE_DIRECT_FILE_ACCESS},
}


@dataclass
class DataFlowTrace:
    """A verified interprocedural dataflow path from source to sink."""

    source_node: GraphNode
    sink_node: GraphNode
    path_nodes: list[GraphNode]
    steps: list[DataFlowStep] = field(default_factory=list)
    category: VulnerabilityCategory = VulnerabilityCategory.GENERIC
    is_sanitized: bool = False
    sanitizer_name: str | None = None
    is_authorized: bool = False
    is_tenant_scoped: bool = False
    confidence: float = 1.0


class SPGDataFlowAnalyzer:
    """Traces attacker-controlled data flows across functions, modules, and components."""

    def __init__(self, graph: SemanticProgramGraph, max_depth: int = 12) -> None:
        self.graph = graph
        self.max_depth = max_depth

    def trace_all_source_to_sinks(self) -> list[DataFlowTrace]:
        """Discover all end-to-end dataflow paths from route parameters to sensitive sinks."""
        traces: list[DataFlowTrace] = []

        # 1. Identify sources (Route parameters and entry point arguments)
        source_nodes: list[GraphNode] = []
        for r in self.graph.find_nodes(kind=NodeKind.ROUTE):
            for edge in self.graph.out_edges.get(r.id, []):
                handler_id = edge.target_id
                for p_edge in self.graph.out_edges.get(handler_id, []):
                    if p_edge.kind in (EdgeKind.DEFINES, EdgeKind.DATA_FLOWS_TO):
                        p_node = self.graph.get_node(p_edge.target_id)
                        if p_node and p_node.kind == NodeKind.PARAMETER:
                            source_nodes.append(p_node)

        # 2. Identify target sinks
        sink_nodes = {
            n.id: n for n in self.graph.nodes.values()
            if n.kind in (
                NodeKind.QUERY,
                NodeKind.PROCESS_EXEC,
                NodeKind.EXTERNAL_REQUEST,
                NodeKind.FILE_OPERATION,
                NodeKind.SENSITIVE_SINK,
            )
        }

        # 3. Breadth-first interprocedural search for each source
        for src in source_nodes:
            discovered = self._trace_from_source(src, sink_nodes)
            traces.extend(discovered)

        return traces

    def _trace_from_source(
        self,
        source: GraphNode,
        sink_nodes: dict[str, GraphNode],
    ) -> list[DataFlowTrace]:
        results: list[DataFlowTrace] = []
        queue: deque[tuple[str, list[str]]] = deque([(source.id, [source.id])])
        visited: set[str] = {source.id}

        allowed_edges = {
            EdgeKind.DATA_FLOWS_TO,
            EdgeKind.PASSES_ARGUMENT,
            EdgeKind.CALLS,
            EdgeKind.REACHES,
            EdgeKind.QUERIES,
            EdgeKind.ACCESSES_RESOURCE,
        }

        while queue:
            curr_id, path = queue.popleft()

            if curr_id in sink_nodes and len(path) > 1:
                sink = sink_nodes[curr_id]
                trace = self._build_trace(source, sink, path)
                results.append(trace)
                continue

            if len(path) >= self.max_depth:
                continue

            for edge in self.graph.out_edges.get(curr_id, []):
                if edge.kind in allowed_edges:
                    target_id = edge.target_id
                    if target_id not in path:  # Cycle safety
                        visited.add(target_id)
                        queue.append((target_id, path + [target_id]))

        return results

    def _build_trace(
        self,
        source: GraphNode,
        sink: GraphNode,
        path_ids: list[str],
    ) -> DataFlowTrace:
        path_nodes = [self.graph.nodes[nid] for nid in path_ids if nid in self.graph.nodes]

        # Determine vulnerability category from sink kind
        category = VulnerabilityCategory.GENERIC
        if sink.kind == NodeKind.QUERY:
            category = VulnerabilityCategory.SQL_INJECTION
        elif sink.kind == NodeKind.PROCESS_EXEC:
            category = VulnerabilityCategory.COMMAND_INJECTION
        elif sink.kind == NodeKind.EXTERNAL_REQUEST:
            category = VulnerabilityCategory.SSRF
        elif sink.kind == NodeKind.FILE_OPERATION:
            category = VulnerabilityCategory.INSECURE_DIRECT_FILE_ACCESS

        # Check for context-sensitive sanitization along the path
        is_sanitized = False
        sanitizer_name = None

        for n in path_nodes:
            # Check outbound sanitizes edges
            for e in self.graph.out_edges.get(n.id, []):
                if e.kind == EdgeKind.SANITIZES:
                    san_node = self.graph.get_node(e.target_id)
                    if san_node:
                        san_short = san_node.label.replace("Sanitizer: ", "").replace("()", "").strip()
                        compat_cats = SANITIZER_COMPATIBILITY.get(san_short, set())
                        if category in compat_cats:
                            is_sanitized = True
                            sanitizer_name = san_short
                            break

        # Check authorization and tenant scoping
        is_authorized = any(n.kind == NodeKind.AUTHORIZATION_CHECK for n in path_nodes)
        is_tenant = any(n.kind == NodeKind.TENANT_CONTEXT for n in path_nodes)

        steps: list[DataFlowStep] = []
        for n in path_nodes:
            steps.append(
                DataFlowStep(
                    location=SourceLocation(
                        file_path=n.file_path,
                        start_line=n.start_line,
                        end_line=n.end_line,
                        symbol=n.label,
                        role="source" if n.id == source.id else ("sink" if n.id == sink.id else "propagation"),
                    ),
                    description=f"{n.kind.value}: {n.label}",
                )
            )

        return DataFlowTrace(
            source_node=source,
            sink_node=sink,
            path_nodes=path_nodes,
            steps=steps,
            category=category,
            is_sanitized=is_sanitized,
            sanitizer_name=sanitizer_name,
            is_authorized=is_authorized,
            is_tenant_scoped=is_tenant,
            confidence=0.95 if not is_sanitized else 0.2,
        )
