"""Graph builder coordinating language frontends and cross-module link resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import (
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RelationshipProvenance,
)
from semantiq.languages.registry import GLOBAL_FRONTEND_REGISTRY
from semantiq.repository.safepath import resolve_safe_path


@dataclass
class GraphBuildResult:
    """Summary of the Semantic Program Graph construction."""

    graph: SemanticProgramGraph
    files_indexed: int
    files_skipped: int
    failed_parsing_files: list[str] = field(default_factory=list)
    gap_notes: list[str] = field(default_factory=list)


class GraphBuilder:
    """Constructs, links, and indexes a Semantic Program Graph for a repository."""

    def __init__(self, repo_root: Path, source_revision: str = "") -> None:
        self.repo_root = repo_root
        self.source_revision = source_revision

    def build(self, in_scope_files: list[str]) -> GraphBuildResult:
        """Parse all in-scope files and resolve cross-file edges."""
        graph = SemanticProgramGraph(
            repository_root=str(self.repo_root),
            source_revision=self.source_revision,
        )

        # Create root Repository node
        repo_node_id = f"repo:{self.repo_root.name}"
        graph.add_node(
            GraphNode(
                id=repo_node_id,
                kind=NodeKind.REPOSITORY,
                label=self.repo_root.name,
                file_path="",
                start_line=1,
                end_line=1,
                provenance=RelationshipProvenance.DIRECT_FACT,
                source_revision=self.source_revision,
            )
        )

        files_indexed = 0
        files_skipped = 0
        failed_files: list[str] = []
        all_gaps: list[str] = []

        # Phase 1: Parse individual files with language frontends
        for rel_path in in_scope_files:
            clean_path = rel_path.replace("\\", "/")
            try:
                full_path = resolve_safe_path(self.repo_root, clean_path)
            except Exception:
                files_skipped += 1
                continue

            if not full_path.exists() or not full_path.is_file():
                files_skipped += 1
                continue

            frontend = GLOBAL_FRONTEND_REGISTRY.get_frontend_for_file(clean_path)
            if not frontend:
                files_skipped += 1
                all_gaps.append(f"No semantic frontend registered for file: {clean_path}")
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError as err:
                failed_files.append(clean_path)
                all_gaps.append(f"Could not read {clean_path}: {err}")
                continue

            result = frontend.parse_file(
                file_path=clean_path,
                source_code=content,
                graph=graph,
                repo_root=self.repo_root,
                source_revision=self.source_revision,
            )

            if result.parsed_successfully:
                files_indexed += 1
                # Connect file to repository
                graph.add_edge(
                    GraphEdge(
                        source_id=repo_node_id,
                        target_id=f"file:{clean_path}",
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )
            else:
                failed_files.append(clean_path)

            if result.gaps:
                all_gaps.extend(result.gaps)

        # Phase 2: Inter-procedural Symbol and Call Resolution
        self._resolve_cross_module_calls(graph)

        return GraphBuildResult(
            graph=graph,
            files_indexed=files_indexed,
            files_skipped=files_skipped,
            failed_parsing_files=failed_files,
            gap_notes=all_gaps,
        )

    def _resolve_cross_module_calls(self, graph: SemanticProgramGraph) -> None:
        """Resolve symbolic calls (e.g. sym:callee_name) to target function nodes across files."""
        # Index all functions and methods by short label
        symbol_targets: dict[str, list[GraphNode]] = {}
        for _nid, node in graph.nodes.items():
            if node.kind in (NodeKind.FUNCTION, NodeKind.METHOD):
                symbol_targets.setdefault(node.label, []).append(node)
                # If qualified (e.g. class.method or func), index short name too
                short_name = node.label.split(".")[-1]
                if short_name != node.label:
                    symbol_targets.setdefault(short_name, []).append(node)

        # Index all classes by label and methods by qualified name
        classes: dict[str, GraphNode] = {n.label: n for n in graph.nodes.values() if n.kind == NodeKind.CLASS}

        # Find unresolved calls and placeholder edges
        edges_to_add: list[GraphEdge] = []
        for source_id, edges in list(graph.out_edges.items()):
            source_node = graph.nodes.get(source_id)
            source_file = source_node.file_path if source_node else ""

            for edge in list(edges):
                if edge.kind == EdgeKind.CALLS and edge.target_id.startswith("sym:") and ":" not in edge.target_id[4:]:
                    callee_name = edge.target_id[4:]
                    imported_from = edge.properties.get("imported_from")
                    is_self_call = edge.properties.get("is_self_call", False)
                    caller_class = edge.properties.get("caller_class")

                    target_node: GraphNode | None = None

                    # 1. Check method inheritance for self calls
                    if is_self_call and caller_class and caller_class in classes:
                        cls_node = classes[caller_class]
                        bases = cls_node.properties.get("bases", [])
                        for base_name in bases:
                            base_qname = f"{base_name}.{callee_name}"
                            base_matches = symbol_targets.get(base_qname, [])
                            if base_matches:
                                target_node = base_matches[0]
                                break

                    # 2. Check import-directed resolution
                    if target_node is None and imported_from:
                        # e.g. "services.tenant_service.get_tenant_document" -> "services/tenant_service"
                        mod_part = imported_from.rsplit(".", 1)[0].replace(".", "/")
                        matched_by_import = [
                            t for t in symbol_targets.get(callee_name, [])
                            if mod_part in t.file_path or t.file_path.endswith(f"{mod_part}.py")
                        ]
                        if len(matched_by_import) == 1:
                            target_node = matched_by_import[0]
                        elif len(matched_by_import) > 1:
                            # Ambiguous across multiple matching files
                            edges_to_add.append(
                                GraphEdge(
                                    source_id=source_id,
                                    target_id=edge.target_id,
                                    kind=EdgeKind.CALLS,
                                    provenance=RelationshipProvenance.UNRESOLVED,
                                    confidence=0.4,
                                    properties={"callee_name": callee_name, "reason": "ambiguous_imported_target"},
                                )
                            )
                            continue

                    # 3. Prefer local file definition if available
                    if target_node is None:
                        candidates = symbol_targets.get(callee_name, [])
                        local_candidates = [t for t in candidates if t.file_path == source_file]
                        if len(local_candidates) == 1:
                            target_node = local_candidates[0]
                        elif len(candidates) == 1:
                            target_node = candidates[0]
                        elif len(candidates) > 1:
                            # Unresolved ambiguous call: do NOT silently link
                            if edge in graph.out_edges.get(source_id, []):
                                graph.out_edges[source_id].remove(edge)
                            edges_to_add.append(
                                GraphEdge(
                                    source_id=source_id,
                                    target_id=edge.target_id,
                                    kind=EdgeKind.CALLS,
                                    provenance=RelationshipProvenance.UNRESOLVED,
                                    confidence=0.3,
                                    properties={
                                        "callee_name": callee_name,
                                        "reason": "ambiguous_cross_module_call",
                                        "candidate_count": len(candidates),
                                    },
                                )
                            )
                            continue

                    if target_node is not None:
                        # Remove placeholder call edge
                        if edge in graph.out_edges.get(source_id, []):
                            graph.out_edges[source_id].remove(edge)

                        # Statically inferred cross-module call edge
                        edges_to_add.append(
                            GraphEdge(
                                source_id=source_id,
                                target_id=target_node.id,
                                kind=EdgeKind.CALLS,
                                provenance=RelationshipProvenance.STATICALLY_INFERRED,
                                confidence=0.95 if imported_from else 0.75,
                                properties={"callee_name": callee_name},
                            )
                        )
                        edges_to_add.append(
                            GraphEdge(
                                source_id=source_id,
                                target_id=target_node.id,
                                kind=EdgeKind.DATA_FLOWS_TO,
                                provenance=RelationshipProvenance.STATICALLY_INFERRED,
                                confidence=0.85,
                            )
                        )
                        # Also add DATA_FLOWS_TO edge from caller to callee's parameters
                        for p_edge in graph.out_edges.get(target_node.id, []):
                            if p_edge.kind == EdgeKind.DEFINES and graph.nodes.get(p_edge.target_id, None) and graph.nodes[p_edge.target_id].kind == NodeKind.PARAMETER:
                                edges_to_add.append(
                                    GraphEdge(
                                        source_id=source_id,
                                        target_id=p_edge.target_id,
                                        kind=EdgeKind.DATA_FLOWS_TO,
                                        provenance=RelationshipProvenance.STATICALLY_INFERRED,
                                        confidence=0.8,
                                    )
                                )
                                edges_to_add.append(
                                    GraphEdge(
                                        source_id=p_edge.target_id,
                                        target_id=target_node.id,
                                        kind=EdgeKind.DATA_FLOWS_TO,
                                        provenance=RelationshipProvenance.STATICALLY_INFERRED,
                                        confidence=0.8,
                                    )
                                )

                        # Connect helper to sinks directly reached by the caller function
                        for sink_edge in edges:
                            if sink_edge.kind in (EdgeKind.REACHES, EdgeKind.QUERIES, EdgeKind.ACCESSES_RESOURCE):
                                edges_to_add.append(
                                    GraphEdge(
                                        source_id=target_node.id,
                                        target_id=sink_edge.target_id,
                                        kind=EdgeKind.DATA_FLOWS_TO,
                                        provenance=RelationshipProvenance.STATICALLY_INFERRED,
                                        confidence=0.8,
                                    )
                                )

        for edge in edges_to_add:
            graph.add_edge(edge)
