"""Tests for persistent storage, incremental updates, and cache invalidation."""

from __future__ import annotations

import tempfile
from pathlib import Path

from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import EdgeKind, GraphEdge, GraphNode, NodeKind, RelationshipProvenance
from semantiq.models import InvestigationHypothesis
from semantiq.storage.sqlite import SQLiteStorage


def test_cold_warm_and_revision_mismatch() -> None:
    """Verify cold indexing, warm caching, and source revision mismatch rejection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "semantiq_audit.db"
        storage = SQLiteStorage(str(db_path))

        repo_id = "test_audit_repo"
        rev_v1 = "commit_sha_111"
        rev_v2 = "commit_sha_222"

        # 1. Cold indexing
        graph_v1 = SemanticProgramGraph(repository_root=repo_id, source_revision=rev_v1)
        node_1 = GraphNode(
            id="sym:app.py:main",
            kind=NodeKind.FUNCTION,
            label="main",
            file_path="app.py",
            start_line=1,
            end_line=10,
            provenance=RelationshipProvenance.DIRECT_FACT,
            source_revision=rev_v1,
        )
        graph_v1.add_node(node_1)
        storage.save_graph(repo_id, rev_v1, graph_v1)

        # 2. Warm indexing - same revision succeeds
        loaded = storage.load_graph(repo_id, rev_v1)
        assert loaded is not None
        assert loaded.source_revision == rev_v1
        assert loaded.get_node(node_1.id) is not None

        # 3. Source revision mismatch - cached graph cannot silently refer to different revision
        mismatch = storage.load_graph(repo_id, rev_v2)
        assert mismatch is None  # Rejects stale revision


def test_incremental_changed_and_deleted_file_indexing() -> None:
    """Verify that incremental updates remove obsolete nodes/edges while preserving unchanged ones."""
    graph = SemanticProgramGraph(repository_root="repo", source_revision="rev_1")

    # File A (will be updated)
    node_a1 = GraphNode(
        id="sym:file_a.py:func_v1",
        kind=NodeKind.FUNCTION,
        label="func_v1",
        file_path="file_a.py",
        start_line=5,
        end_line=10,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    # File B (will be deleted)
    node_b = GraphNode(
        id="sym:file_b.py:helper",
        kind=NodeKind.FUNCTION,
        label="helper",
        file_path="file_b.py",
        start_line=1,
        end_line=5,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    # File C (will remain unchanged)
    node_c = GraphNode(
        id="sym:file_c.py:stable",
        kind=NodeKind.FUNCTION,
        label="stable",
        file_path="file_c.py",
        start_line=1,
        end_line=5,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )

    graph.add_node(node_a1)
    graph.add_node(node_b)
    graph.add_node(node_c)

    # Cross-file edges: A -> B, A -> C
    graph.add_edge(GraphEdge(source_id=node_a1.id, target_id=node_b.id, kind=EdgeKind.CALLS))
    graph.add_edge(GraphEdge(source_id=node_a1.id, target_id=node_c.id, kind=EdgeKind.CALLS))

    assert len(graph.nodes) == 3
    assert len(graph.out_edges.get(node_a1.id, [])) == 2

    # 1. Deleted-file indexing: delete file_b.py
    removed_count = graph.remove_file("file_b.py")
    assert removed_count == 1
    assert graph.get_node(node_b.id) is None
    # Verify inbound edge to deleted node disappeared
    a_targets = [e.target_id for e in graph.out_edges.get(node_a1.id, [])]
    assert node_b.id not in a_targets
    assert node_c.id in a_targets

    # 2. Changed-file indexing: update file_a.py
    graph.remove_file("file_a.py")
    assert graph.get_node(node_a1.id) is None

    # Add updated version of file_a
    node_a2 = GraphNode(
        id="sym:file_a.py:func_v2",
        kind=NodeKind.FUNCTION,
        label="func_v2",
        file_path="file_a.py",
        start_line=20,
        end_line=30,
        provenance=RelationshipProvenance.DIRECT_FACT,
    )
    graph.add_node(node_a2)
    graph.add_edge(GraphEdge(source_id=node_a2.id, target_id=node_c.id, kind=EdgeKind.CALLS))

    # Verify state after incremental updates
    assert graph.get_node(node_a1.id) is None  # Obsolete node gone
    assert graph.get_node(node_a2.id) is not None  # Updated node present
    assert graph.get_node(node_c.id) is not None  # Unchanged node intact
    assert len(graph.out_edges.get(node_a2.id, [])) == 1
    assert graph.out_edges[node_a2.id][0].target_id == node_c.id


def test_investigation_memory_tied_to_revision() -> None:
    """Verify that investigation hypotheses are saved and scoped to scan and revision."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        storage = SQLiteStorage(str(db_path))

        repo = "my_saas"
        scan_id_v1 = "scan_rev_111"
        scan_id_v2 = "scan_rev_222"

        hyp = InvestigationHypothesis(
            hypothesis_id="hyp_001",
            statement="Missing tenant check on document_view",
            target_symbol="document_view",
            entry_point="/api/v1/tenant/documents/<doc_id>",
            sensitive_operation="cursor.execute(SELECT * FROM documents WHERE id = ?)",
            rule_id="SQ-PY-015",
            disposition="confirmed",
        )

        storage.save_hypothesis(hypothesis=hyp, scan_id=scan_id_v1, repo_path=repo)

        hyps = storage.get_hypotheses(scan_id=scan_id_v1)
        assert len(hyps) == 1
        assert hyps[0].target_symbol == "document_view"
        assert hyps[0].disposition == "confirmed"

        # Hypotheses from other scan/revision are not returned
        other_hyps = storage.get_hypotheses(scan_id=scan_id_v2)
        assert len(other_hyps) == 0
