"""SQLite persistence layer for scans, findings, threat models, patches, and semantic graphs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from semantiq.exceptions import StorageError
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import (
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RelationshipProvenance,
)
from semantiq.models import (
    Finding,
    InvestigationHypothesis,
    InvestigationMemoryRecord,
    ScanResult,
)

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    git_revision TEXT,
    mode TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    inspection_json TEXT NOT NULL,
    coverage_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    validation_status TEXT NOT NULL,
    full_json TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_models (
    scan_id TEXT PRIMARY KEY,
    repository_path TEXT NOT NULL,
    full_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS validations (
    finding_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    mode TEXT NOT NULL,
    summary TEXT NOT NULL,
    full_json TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS patches (
    finding_id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    unified_diff TEXT NOT NULL,
    rationale TEXT NOT NULL,
    applied INTEGER NOT NULL,
    full_json TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

-- Phase 6: Persistent Repository Memory and Semantic Program Graph
CREATE TABLE IF NOT EXISTS repository_memory (
    repo_path TEXT NOT NULL,
    source_revision TEXT NOT NULL,
    architecture_summary_json TEXT NOT NULL,
    entry_points_json TEXT NOT NULL,
    security_boundaries_json TEXT NOT NULL,
    analysis_gaps_json TEXT NOT NULL,
    memory_json TEXT DEFAULT '{}',
    updated_at TEXT NOT NULL,
    PRIMARY KEY(repo_path, source_revision)
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    source_revision TEXT NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    provenance TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    PRIMARY KEY(node_id, repo_path, source_revision)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    repo_path TEXT NOT NULL,
    source_revision TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    provenance TEXT NOT NULL,
    confidence REAL NOT NULL,
    properties_json TEXT NOT NULL,
    PRIMARY KEY(repo_path, source_revision, source_id, target_id, kind)
);

CREATE TABLE IF NOT EXISTS investigation_hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    target_symbol TEXT NOT NULL,
    entry_point TEXT NOT NULL,
    statement TEXT NOT NULL,
    disposition TEXT NOT NULL,
    full_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class SQLiteStorage:
    """Thread-safe SQLite storage engine for Semantiq Security."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._mem_conn: sqlite3.Connection | None = None
        if db_path != ":memory:":
            p = Path(db_path).expanduser().resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(p)
        else:
            self.db_path = ":memory:"
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        self._init_db()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._mem_conn is not None:
            yield self._mem_conn
        else:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            try:
                yield conn
            finally:
                conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.executescript(SCHEMA_V2)
            with suppress(sqlite3.OperationalError):
                conn.execute("ALTER TABLE repository_memory ADD COLUMN memory_json TEXT DEFAULT '{}';")
            cur = conn.execute("SELECT version FROM schema_version;")
            row = cur.fetchone()
            if not row:
                conn.execute("INSERT INTO schema_version (version) VALUES (2);")
            else:
                conn.execute("UPDATE schema_version SET version = 2;")
            conn.commit()

    def save_scan(self, scan_result: ScanResult) -> None:
        """Persist a complete scan result and all associated findings and threat model."""
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scans
                    (scan_id, target_path, git_revision, mode, started_at, completed_at, inspection_json, coverage_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        scan_result.scan_id,
                        scan_result.target_path,
                        scan_result.git_revision,
                        scan_result.mode,
                        scan_result.started_at,
                        scan_result.completed_at,
                        scan_result.inspection.model_dump_json(),
                        json.dumps(scan_result.coverage_summary),
                    ),
                )

                for finding in scan_result.findings:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO findings
                        (finding_id, scan_id, rule_id, title, category, severity, confidence, file_path, start_line, end_line, fingerprint, validation_status, full_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            finding.finding_id,
                            scan_result.scan_id,
                            finding.rule_id,
                            finding.title,
                            finding.category.value,
                            finding.severity.value,
                            finding.confidence.value,
                            finding.file_path,
                            finding.start_line,
                            finding.end_line,
                            finding.fingerprint,
                            finding.validation_status.value,
                            finding.model_dump_json(),
                        ),
                    )

                if scan_result.threat_model:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO threat_models
                        (scan_id, repository_path, full_json, created_at)
                        VALUES (?, ?, ?, ?);
                        """,
                        (
                            scan_result.scan_id,
                            scan_result.threat_model.repository_path,
                            scan_result.threat_model.model_dump_json(),
                            scan_result.threat_model.created_at,
                        ),
                    )
        except sqlite3.Error as error:
            raise StorageError(f"Database error while saving scan: {error}") from error

    def get_findings_by_scan(self, scan_id: str) -> list[Finding]:
        """Retrieve all findings recorded for a given scan."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT full_json FROM findings WHERE scan_id = ? ORDER BY severity ASC;",
                    (scan_id,),
                )
                rows = cur.fetchall()
                return [Finding.model_validate_json(row["full_json"]) for row in rows]
        except sqlite3.Error as error:
            raise StorageError(f"Database error fetching findings: {error}") from error

    def get_finding_by_id(self, finding_id: str) -> Finding | None:
        """Fetch a specific finding by identifier."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT full_json FROM findings WHERE finding_id = ?;",
                    (finding_id,),
                )
                row = cur.fetchone()
                if row:
                    return Finding.model_validate_json(row["full_json"])
                return None
        except sqlite3.Error as error:
            raise StorageError(f"Database error fetching finding {finding_id}: {error}") from error

    def list_scans(self) -> list[dict[str, Any]]:
        """List summary of recorded scans."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT scan_id, target_path, git_revision, mode, started_at, completed_at FROM scans ORDER BY started_at DESC;"
                )
                return [dict(row) for row in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(f"Database error listing scans: {error}") from error

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all associated records."""
        try:
            with self._connection() as conn, conn:
                cur = conn.execute("DELETE FROM scans WHERE scan_id = ?;", (scan_id,))
                return cur.rowcount > 0
        except sqlite3.Error as error:
            raise StorageError(f"Database error deleting scan {scan_id}: {error}") from error

    # Phase 6 Persistent Graph & Repository Memory methods
    def save_graph(self, repo_path: str, source_revision: str, graph: SemanticProgramGraph) -> None:
        """Persist Semantic Program Graph nodes and edges for incremental updates."""
        try:
            with self._connection() as conn, conn:
                # Remove stale graph records for this revision
                conn.execute(
                    "DELETE FROM graph_nodes WHERE repo_path = ? AND source_revision = ?;",
                    (repo_path, source_revision),
                )
                conn.execute(
                    "DELETE FROM graph_edges WHERE repo_path = ? AND source_revision = ?;",
                    (repo_path, source_revision),
                )

                for node in graph.nodes.values():
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO graph_nodes
                        (node_id, repo_path, source_revision, kind, label, file_path, start_line, end_line, provenance, properties_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            node.id,
                            repo_path,
                            source_revision,
                            node.kind.value,
                            node.label,
                            node.file_path,
                            node.start_line,
                            node.end_line,
                            node.provenance.value,
                            json.dumps(node.properties),
                        ),
                    )

                for edges in graph.out_edges.values():
                    for edge in edges:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO graph_edges
                            (repo_path, source_revision, source_id, target_id, kind, provenance, confidence, properties_json)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                            """,
                            (
                                repo_path,
                                source_revision,
                                edge.source_id,
                                edge.target_id,
                                edge.kind.value,
                                edge.provenance.value,
                                edge.confidence,
                                json.dumps(edge.properties),
                            ),
                        )
        except sqlite3.Error as error:
            raise StorageError(f"Database error saving semantic graph: {error}") from error

    def load_graph(self, repo_path: str, source_revision: str) -> SemanticProgramGraph | None:
        """Load persisted Semantic Program Graph from storage if present."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM graph_nodes WHERE repo_path = ? AND source_revision = ?;",
                    (repo_path, source_revision),
                )
                node_rows = cur.fetchall()
                if not node_rows:
                    return None

                graph = SemanticProgramGraph(repository_root=repo_path, source_revision=source_revision)
                for r in node_rows:
                    node = GraphNode(
                        id=r["node_id"],
                        kind=NodeKind(r["kind"]),
                        label=r["label"],
                        file_path=r["file_path"],
                        start_line=r["start_line"],
                        end_line=r["end_line"],
                        provenance=RelationshipProvenance(r["provenance"]),
                        source_revision=r["source_revision"],
                        properties=json.loads(r["properties_json"]),
                    )
                    graph.add_node(node)

                cur_edges = conn.execute(
                    "SELECT * FROM graph_edges WHERE repo_path = ? AND source_revision = ?;",
                    (repo_path, source_revision),
                )
                for r in cur_edges.fetchall():
                    edge = GraphEdge(
                        source_id=r["source_id"],
                        target_id=r["target_id"],
                        kind=EdgeKind(r["kind"]),
                        provenance=RelationshipProvenance(r["provenance"]),
                        confidence=r["confidence"],
                        properties=json.loads(r["properties_json"]),
                    )
                    graph.add_edge(edge)

                return graph
        except sqlite3.Error as error:
            raise StorageError(f"Database error loading semantic graph: {error}") from error

    def save_hypothesis(self, hypothesis: InvestigationHypothesis, scan_id: str, repo_path: str) -> None:
        """Persist structured investigation hypothesis."""
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO investigation_hypotheses
                    (hypothesis_id, scan_id, repo_path, target_symbol, entry_point, statement, disposition, full_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'));
                    """,
                    (
                        hypothesis.hypothesis_id,
                        scan_id,
                        repo_path,
                        hypothesis.target_symbol,
                        hypothesis.entry_point,
                        hypothesis.statement,
                        hypothesis.disposition,
                        hypothesis.model_dump_json(),
                    ),
                )
        except sqlite3.Error as error:
            raise StorageError(f"Database error saving hypothesis: {error}") from error

    def get_hypotheses(self, scan_id: str) -> list[InvestigationHypothesis]:
        """Fetch all hypotheses recorded for a scan."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT full_json FROM investigation_hypotheses WHERE scan_id = ?;",
                    (scan_id,),
                )
                return [InvestigationHypothesis.model_validate_json(row["full_json"]) for row in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(f"Database error fetching hypotheses: {error}") from error

    def save_repository_memory(self, memory: InvestigationMemoryRecord) -> None:
        """Persist structured repository memory and security architecture model."""
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO repository_memory
                    (repo_path, source_revision, architecture_summary_json, entry_points_json, security_boundaries_json, analysis_gaps_json, memory_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        memory.repo_path,
                        memory.source_revision,
                        json.dumps(memory.architecture_summary),
                        json.dumps(memory.entry_points),
                        json.dumps(memory.security_boundaries),
                        json.dumps(memory.analysis_gaps),
                        memory.model_dump_json(),
                        memory.updated_at,
                    ),
                )
        except sqlite3.Error as error:
            raise StorageError(f"Database error saving repository memory: {error}") from error

    def load_repository_memory(self, repo_path: str, source_revision: str) -> InvestigationMemoryRecord | None:
        """Load persistent repository memory for a given path and revision."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM repository_memory WHERE repo_path = ? AND source_revision = ?;",
                    (repo_path, source_revision),
                )
                row = cur.fetchone()
                if not row:
                    return None

                row_dict = dict(row)
                memory_raw = row_dict.get("memory_json")
                if memory_raw and memory_raw != "{}":
                    try:
                        return InvestigationMemoryRecord.model_validate_json(memory_raw)
                    except Exception:
                        pass

                return InvestigationMemoryRecord(
                    repo_path=row["repo_path"],
                    source_revision=row["source_revision"],
                    architecture_summary=json.loads(row["architecture_summary_json"]),
                    entry_points=json.loads(row["entry_points_json"]),
                    security_boundaries=json.loads(row["security_boundaries_json"]),
                    analysis_gaps=json.loads(row["analysis_gaps_json"]),
                    updated_at=row["updated_at"],
                )
        except sqlite3.Error as error:
            raise StorageError(f"Database error loading repository memory: {error}") from error

    def invalidate_stale_memory(self, repo_path: str, current_revision: str) -> int:
        """Invalidate obsolete graph and memory caches when source code revision changes."""
        if not current_revision:
            return 0
        try:
            with self._connection() as conn, conn:
                cur_mem = conn.execute(
                    "DELETE FROM repository_memory WHERE repo_path = ? AND source_revision != ? AND source_revision != '';",
                    (repo_path, current_revision),
                )
                cur_nodes = conn.execute(
                    "DELETE FROM graph_nodes WHERE repo_path = ? AND source_revision != ? AND source_revision != '';",
                    (repo_path, current_revision),
                )
                cur_edges = conn.execute(
                    "DELETE FROM graph_edges WHERE repo_path = ? AND source_revision != ? AND source_revision != '';",
                    (repo_path, current_revision),
                )
                return cur_mem.rowcount + cur_nodes.rowcount + cur_edges.rowcount
        except sqlite3.Error as error:
            raise StorageError(f"Database error invalidating stale memory: {error}") from error
