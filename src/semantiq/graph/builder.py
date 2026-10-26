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

        # Find unresolved calls and placeholder edges
        edges_to_add: list[GraphEdge] = []
        for source_id, edges in list(graph.out_edges.items()):
            for edge in list(edges):
                if edge.kind == EdgeKind.CALLS and edge.target_id.startswith("sym:") and ":" not in edge.target_id[4:]:
                    callee_name = edge.target_id[4:]
                    targets = symbol_targets.get(callee_name, [])
                    if targets:
                        target_node = targets[0]
                        # Statically inferred cross-module call edge
                        edges_to_add.append(
                            GraphEdge(
                                source_id=source_id,
                                target_id=target_node.id,
                                kind=EdgeKind.CALLS,
                                provenance=RelationshipProvenance.STATICALLY_INFERRED,
                                confidence=0.9 if len(targets) == 1 else 0.6,
                                properties={"callee_name": callee_name, "candidates": len(targets)},
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
                                edges_to_add.append(
                                    GraphEdge(
                                        source_id=source_id,
                                        target_id=p_edge.target_id,
                                        kind=EdgeKind.DATA_FLOWS_TO,
                                        provenance=RelationshipProvenance.STATICALLY_INFERRED,
                                        confidence=0.8,
                                    )
                                )

        for edge in edges_to_add:
            graph.add_edge(edge)
