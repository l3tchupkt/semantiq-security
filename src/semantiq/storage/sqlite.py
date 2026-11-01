"""SQLite persistence layer for scans, findings, threat models, patches, and semantic graphs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
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
    CodeEvidence,
    CodeEvidenceRole,
    EvidenceProvenance,
    EvidenceVerificationStatus,
    Finding,
    InvestigationHypothesis,
    InvestigationMemoryRecord,
    ProofGap,
    ProofGapStatus,
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

SCHEMA_V3 = """
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
    lifecycle_state TEXT DEFAULT 'candidate',
    root_cause_refs_json TEXT DEFAULT '[]',
    proof_gaps_json TEXT DEFAULT '[]',
    semantic_identity_json TEXT DEFAULT '{}',
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

-- Phase 7: Structured Semantic Evidence Contract, Proof Gaps & Finalization
CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    role TEXT NOT NULL,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    snippet TEXT NOT NULL,
    explanation TEXT DEFAULT '',
    provenance TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence_references (
    reference_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    step_order INTEGER NOT NULL,
    role TEXT NOT NULL,
    description TEXT DEFAULT '',
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY(evidence_id) REFERENCES evidence_records(evidence_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS proof_gaps (
    gap_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    target_symbol TEXT DEFAULT '',
    description TEXT NOT NULL,
    rationale TEXT DEFAULT '',
    resolution_criteria TEXT DEFAULT '',
    status TEXT NOT NULL,
    supporting_evidence_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS adjudications (
    adjudication_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    validity TEXT NOT NULL,
    exploitability_confidence TEXT NOT NULL,
    severity TEXT NOT NULL,
    reasoning TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finalization_results (
    scan_id TEXT PRIMARY KEY,
    is_sealed INTEGER NOT NULL,
    violation_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    warning_count INTEGER NOT NULL,
    violations_json TEXT NOT NULL,
    sarif_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    finalized_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
"""

SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS investigation_runs (
    run_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    repository_path TEXT NOT NULL,
    source_revision TEXT NOT NULL,
    mode TEXT NOT NULL,
    max_concurrent_workers INTEGER NOT NULL,
    packets_count INTEGER NOT NULL,
    workers_count INTEGER NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cached_input_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,
    security_score REAL NOT NULL,
    duration_seconds REAL NOT NULL,
    is_sealed INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigation_packets (
    packet_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    title TEXT NOT NULL,
    focus_category TEXT NOT NULL,
    priority INTEGER NOT NULL,
    status TEXT NOT NULL,
    target_symbols_json TEXT NOT NULL,
    entrypoints_json TEXT NOT NULL,
    sinks_json TEXT NOT NULL,
    file_paths_json TEXT NOT NULL,
    assigned_worker_id TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(run_id) REFERENCES investigation_runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS worker_executions (
    worker_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    packet_id TEXT NOT NULL,
    role TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cached_input_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,
    duration_seconds REAL NOT NULL,
    is_successful INTEGER NOT NULL,
    error_message TEXT,
    executed_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES investigation_runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reducer_decisions (
    decision_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL,
    contributing_workers_json TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES investigation_runs(run_id) ON DELETE CASCADE
);
"""

SCHEMA_V5 = """
CREATE TABLE IF NOT EXISTS finding_versions (
    version_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    lifecycle_state TEXT NOT NULL,
    confidence TEXT NOT NULL,
    severity TEXT NOT NULL,
    semantic_identity_json TEXT NOT NULL DEFAULT '{}',
    snapshot_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(finding_id, version_number),
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS lifecycle_transitions (
    transition_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    trigger_reason TEXT NOT NULL,
    actor_or_component TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS semantic_merges (
    merge_id TEXT PRIMARY KEY,
    primary_finding_id TEXT NOT NULL,
    secondary_finding_id TEXT NOT NULL,
    decision_outcome TEXT NOT NULL,
    equivalence_confidence REAL NOT NULL,
    merge_rationale TEXT NOT NULL,
    evidence_ids_merged_json TEXT NOT NULL DEFAULT '[]',
    contributing_workers_json TEXT NOT NULL DEFAULT '[]',
    merged_at TEXT NOT NULL,
    FOREIGN KEY(primary_finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY(secondary_finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS provider_usage (
    usage_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    model_name TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    cached_input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,
    estimated_cost_usd REAL NOT NULL DEFAULT 0.0,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_versions_finding_id ON finding_versions(finding_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_transitions_finding_id ON lifecycle_transitions(finding_id);
CREATE INDEX IF NOT EXISTS idx_semantic_merges_primary ON semantic_merges(primary_finding_id);
CREATE INDEX IF NOT EXISTS idx_semantic_merges_secondary ON semantic_merges(secondary_finding_id);
CREATE INDEX IF NOT EXISTS idx_provider_usage_run_id ON provider_usage(run_id);
"""

SCHEMA_V6 = """
CREATE TABLE IF NOT EXISTS deep_scan_runs (
    scan_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL DEFAULT 6,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    mode TEXT NOT NULL,
    workers_limit INTEGER NOT NULL,
    packets_total INTEGER NOT NULL DEFAULT 0,
    packets_completed INTEGER NOT NULL DEFAULT 0,
    packets_failed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    terminal_reason TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS deep_scan_packets (
    packet_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    status TEXT NOT NULL,
    target_symbols_json TEXT NOT NULL DEFAULT '[]',
    target_files_json TEXT NOT NULL DEFAULT '[]',
    assigned_skills_json TEXT NOT NULL DEFAULT '[]',
    budget_json TEXT NOT NULL DEFAULT '{}',
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES deep_scan_runs(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS packet_transitions (
    transition_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deep_worker_executions (
    worker_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    packet_id TEXT NOT NULL,
    skill_id TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_seconds REAL NOT NULL,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES deep_scan_runs(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_deep_scan_packets_scan_id ON deep_scan_packets(scan_id);
CREATE INDEX IF NOT EXISTS idx_packet_transitions_packet_id ON packet_transitions(packet_id);
CREATE INDEX IF NOT EXISTS idx_deep_worker_executions_scan_id ON deep_worker_executions(scan_id);
CREATE INDEX IF NOT EXISTS idx_deep_worker_executions_packet_id ON deep_worker_executions(packet_id);
"""


VALID_LIFECYCLE_STATES = {
    "candidate",
    "under_investigation",
    "confirmed",
    "partially_confirmed",
    "rejected",
    "duplicate",
    "deferred",
}


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
            conn.executescript(SCHEMA_V3)
            conn.executescript(SCHEMA_V4)
            conn.executescript(SCHEMA_V5)
            conn.executescript(SCHEMA_V6)
            with suppress(sqlite3.OperationalError):
                conn.execute(
                    "ALTER TABLE repository_memory ADD COLUMN memory_json TEXT DEFAULT '{}';"
                )
            with suppress(sqlite3.OperationalError):
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN lifecycle_state TEXT DEFAULT 'candidate';"
                )
            with suppress(sqlite3.OperationalError):
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN root_cause_refs_json TEXT DEFAULT '[]';"
                )
            with suppress(sqlite3.OperationalError):
                conn.execute("ALTER TABLE findings ADD COLUMN proof_gaps_json TEXT DEFAULT '[]';")
            with suppress(sqlite3.OperationalError):
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN semantic_identity_json TEXT DEFAULT '{}';"
                )
            with suppress(sqlite3.OperationalError):
                conn.execute(
                    "ALTER TABLE finding_versions ADD COLUMN semantic_identity_json TEXT NOT NULL DEFAULT '{}';"
                )
            with suppress(sqlite3.OperationalError):
                conn.execute(
                    "ALTER TABLE finding_versions ADD COLUMN snapshot_json TEXT NOT NULL DEFAULT '{}';"
                )
            # Non-destructive version reconciliation: archive duplicates before unique index creation
            with suppress(sqlite3.OperationalError):
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS archived_finding_versions (
                        archive_id TEXT PRIMARY KEY,
                        version_id TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        version_number INTEGER NOT NULL,
                        lifecycle_state TEXT NOT NULL,
                        confidence TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        semantic_identity_json TEXT NOT NULL DEFAULT '{}',
                        snapshot_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        archived_at TEXT NOT NULL,
                        archived_reason TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    INSERT INTO archived_finding_versions (
                        archive_id, version_id, finding_id, version_number,
                        lifecycle_state, confidence, severity, semantic_identity_json,
                        snapshot_json, created_at, archived_at, archived_reason
                    )
                    SELECT
                        'arch_' || version_id || '_' || substr(hex(randomblob(4)), 1, 8),
                        version_id, finding_id, version_number,
                        lifecycle_state, confidence, severity, semantic_identity_json,
                        snapshot_json, created_at, datetime('now'),
                        'Duplicate version reconciliation for unique constraint'
                    FROM finding_versions
                    WHERE rowid NOT IN (
                        SELECT MAX(rowid)
                        FROM finding_versions
                        GROUP BY finding_id, version_number
                    );
                    """
                )
                conn.execute(
                    """
                    DELETE FROM finding_versions
                    WHERE rowid NOT IN (
                        SELECT MAX(rowid)
                        FROM finding_versions
                        GROUP BY finding_id, version_number
                    );
                    """
                )
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_versions_finding_version ON finding_versions(finding_id, version_number);"
                )

            # Enforce foreign key constraints for existing V5 databases on semantic_merges
            with suppress(sqlite3.OperationalError):
                cur = conn.execute("PRAGMA foreign_key_list(semantic_merges);")
                fks = cur.fetchall()
                has_secondary_fk = (
                    any(
                        fk[3] == "secondary_finding_id" or fk["from"] == "secondary_finding_id"
                        for fk in fks
                    )
                    if fks
                    else False
                )
                if not has_secondary_fk and fks:
                    conn.execute("ALTER TABLE semantic_merges RENAME TO semantic_merges_legacy;")
                    conn.execute(
                        """
                        CREATE TABLE semantic_merges (
                            merge_id TEXT PRIMARY KEY,
                            primary_finding_id TEXT NOT NULL,
                            secondary_finding_id TEXT NOT NULL,
                            decision_outcome TEXT NOT NULL,
                            equivalence_confidence REAL NOT NULL,
                            merge_rationale TEXT NOT NULL,
                            evidence_ids_merged_json TEXT NOT NULL DEFAULT '[]',
                            contributing_workers_json TEXT NOT NULL DEFAULT '[]',
                            merged_at TEXT NOT NULL,
                            FOREIGN KEY(primary_finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
                            FOREIGN KEY(secondary_finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
                        );
                        """
                    )
                    conn.execute(
                        "INSERT INTO semantic_merges SELECT * FROM semantic_merges_legacy;"
                    )
                    conn.execute("DROP TABLE semantic_merges_legacy;")
            cur = conn.execute("SELECT version FROM schema_version;")
            row = cur.fetchone()
            if not row:
                conn.execute("INSERT INTO schema_version (version) VALUES (5);")
            else:
                conn.execute("UPDATE schema_version SET version = 5;")
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
                    self._save_finding_records(conn, finding, scan_result.scan_id)

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

    def _save_finding_records(
        self, conn: sqlite3.Connection, finding: Finding, scan_id: str
    ) -> None:
        """Persist finding and its normalized evidence, references, proof gaps, and adjudication."""
        target_scan_id = scan_id or finding.scan_id or "default_scan"
        conn.execute(
            """
            INSERT OR IGNORE INTO scans
            (scan_id, target_path, mode, started_at, completed_at, inspection_json, coverage_json)
            VALUES (?, '', 'finding_record', datetime('now'), datetime('now'), '{}', '{}');
            """,
            (target_scan_id,),
        )
        semantic_id_val = getattr(finding, "semantic_identity", None)
        if semantic_id_val is None and finding.metadata and "semantic_identity" in finding.metadata:
            semantic_id_val = finding.metadata["semantic_identity"]
        semantic_id_json = "{}"
        if semantic_id_val:
            if hasattr(semantic_id_val, "model_dump_json"):
                semantic_id_json = semantic_id_val.model_dump_json()
            elif isinstance(semantic_id_val, dict):
                semantic_id_json = json.dumps(semantic_id_val)

        conn.execute(
            """
            INSERT OR REPLACE INTO findings
            (finding_id, scan_id, rule_id, title, category, severity, confidence, file_path, start_line, end_line, fingerprint, validation_status, full_json, lifecycle_state, root_cause_refs_json, proof_gaps_json, semantic_identity_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                finding.finding_id,
                target_scan_id,
                finding.rule_id,
                finding.title,
                finding.category.value,
                finding.severity.value,
                finding.confidence.value,
                finding.file_path,
                finding.start_line,
                finding.end_line,
                finding.fingerprint or finding.calculate_fingerprint(),
                finding.validation_status.value,
                finding.model_dump_json(),
                finding.lifecycle_state.value,
                json.dumps(finding.root_cause_evidence_refs),
                json.dumps([pg.model_dump() for pg in finding.proof_gaps]),
                semantic_id_json,
            ),
        )

        for ev in finding.code_evidence:
            ev_id = ev.ensure_id()
            role_str = ev.role.value if isinstance(ev.role, CodeEvidenceRole) else str(ev.role)
            prov_str = (
                ev.provenance.value
                if isinstance(ev.provenance, EvidenceProvenance)
                else str(ev.provenance)
            )
            stat_str = (
                ev.verification_status.value
                if isinstance(ev.verification_status, EvidenceVerificationStatus)
                else str(ev.verification_status)
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence_records
                (evidence_id, finding_id, role, file_path, start_line, end_line, snippet, explanation, provenance, verification_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'));
                """,
                (
                    ev_id,
                    finding.finding_id,
                    role_str,
                    ev.file_path or finding.file_path,
                    ev.start_line,
                    ev.end_line,
                    ev.snippet,
                    ev.explanation,
                    prov_str,
                    stat_str,
                ),
            )

        refs = finding.root_cause_evidence_refs or [ev.evidence_id for ev in finding.code_evidence]
        for step_idx, ref_id in enumerate(refs, start=1):
            ref_pk = f"ref_{finding.finding_id}_{ref_id}_{step_idx}"
            ev_match = next((e for e in finding.code_evidence if e.evidence_id == ref_id), None)
            role_str = (
                (
                    ev_match.role.value
                    if isinstance(ev_match.role, CodeEvidenceRole)
                    else str(ev_match.role)
                )
                if ev_match
                else "sink"
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence_references
                (reference_id, finding_id, evidence_id, step_order, role, description)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    ref_pk,
                    finding.finding_id,
                    ref_id,
                    step_idx,
                    role_str,
                    ev_match.explanation if ev_match else "",
                ),
            )

        for pg in finding.proof_gaps:
            gap_id = pg.ensure_id()
            status_str = (
                pg.status.value if isinstance(pg.status, ProofGapStatus) else str(pg.status)
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO proof_gaps
                (gap_id, finding_id, target_symbol, description, rationale, resolution_criteria, status, supporting_evidence_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'));
                """,
                (
                    gap_id,
                    finding.finding_id,
                    pg.target_symbol,
                    pg.description,
                    pg.rationale,
                    pg.resolution_criteria,
                    status_str,
                    json.dumps(pg.supporting_evidence),
                ),
            )

        adj_id = f"adj_{finding.finding_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        conn.execute(
            """
            INSERT OR REPLACE INTO adjudications
            (adjudication_id, finding_id, validity, exploitability_confidence, severity, reasoning, lifecycle_state, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'));
            """,
            (
                adj_id,
                finding.finding_id,
                finding.validation_status.value,
                finding.confidence.value,
                finding.severity.value,
                finding.summary,
                finding.lifecycle_state.value,
            ),
        )

    def save_finding(self, finding: Finding, scan_id: str = "") -> None:
        """Persist a single finding and its normalized relational evidence model."""
        try:
            with self._connection() as conn, conn:
                self._save_finding_records(conn, finding, scan_id)
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error saving finding {finding.finding_id}: {error}"
            ) from error

    def save_findings_batch(self, findings: list[Finding], scan_id: str = "") -> None:
        """Persist a batch of findings within a single transaction for high performance."""
        if not findings:
            return
        try:
            with self._connection() as conn, conn:
                for finding in findings:
                    self._save_finding_records(conn, finding, scan_id)
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error batch saving {len(findings)} findings: {error}"
            ) from error

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

    def save_finalization_report(self, report: Any, scan_id: str | None = None) -> None:
        """Persist deterministic scan-contract finalization report and finalized findings."""
        target_scan_id: str = str(scan_id or getattr(report, "scan_id", "default_scan"))
        try:
            with self._connection() as conn, conn:
                # Ensure parent scan record exists to satisfy foreign key constraints
                conn.execute(
                    """
                    INSERT OR IGNORE INTO scans
                    (scan_id, target_path, mode, started_at, completed_at, inspection_json, coverage_json)
                    VALUES (?, '', 'finalization', datetime('now'), datetime('now'), '{}', '{}');
                    """,
                    (target_scan_id,),
                )
                violations_data = [
                    v.to_dict() if hasattr(v, "to_dict") else v
                    for v in getattr(report, "violations", [])
                ]
                conn.execute(
                    """
                    INSERT OR REPLACE INTO finalization_results
                    (scan_id, is_sealed, violation_count, error_count, warning_count, violations_json, sarif_json, manifest_json, finalized_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        target_scan_id,
                        1 if getattr(report, "is_sealed", False) else 0,
                        len(getattr(report, "violations", [])),
                        getattr(report, "error_count", 0),
                        getattr(report, "warning_count", 0),
                        json.dumps(violations_data),
                        getattr(report, "sarif_output", ""),
                        getattr(report, "sealed_manifest_json", ""),
                        getattr(report, "finalized_at", datetime.now(timezone.utc).isoformat()),
                    ),
                )

                for f in getattr(report, "finalized_findings", []):
                    self._save_finding_records(conn, f, target_scan_id)
        except sqlite3.Error as error:
            raise StorageError(f"Database error saving finalization report: {error}") from error

    def get_finalization_report(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve scan-contract finalization result for a scan."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM finalization_results WHERE scan_id = ?;",
                    (scan_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                d = dict(row)
                d["violations"] = json.loads(d["violations_json"])
                return d
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error fetching finalization report for {scan_id}: {error}"
            ) from error

    def get_evidence_records(self, finding_id: str) -> list[CodeEvidence]:
        """Fetch all normalized semantic code evidence records for a finding."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM evidence_records WHERE finding_id = ? ORDER BY start_line ASC;",
                    (finding_id,),
                )
                records: list[CodeEvidence] = []
                for r in cur.fetchall():
                    records.append(
                        CodeEvidence(
                            evidence_id=r["evidence_id"],
                            file_path=r["file_path"],
                            start_line=r["start_line"],
                            end_line=r["end_line"],
                            snippet=r["snippet"],
                            role=CodeEvidenceRole(r["role"])
                            if r["role"] in [e.value for e in CodeEvidenceRole]
                            else r["role"],
                            explanation=r["explanation"] or "",
                            provenance=EvidenceProvenance(r["provenance"])
                            if r["provenance"] in [e.value for e in EvidenceProvenance]
                            else r["provenance"],
                            verification_status=EvidenceVerificationStatus(r["verification_status"])
                            if r["verification_status"]
                            in [e.value for e in EvidenceVerificationStatus]
                            else r["verification_status"],
                        )
                    )
                return records
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error fetching evidence records for {finding_id}: {error}"
            ) from error

    def get_proof_gaps(self, finding_id: str) -> list[ProofGap]:
        """Fetch all proof gaps recorded for a finding."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM proof_gaps WHERE finding_id = ?;",
                    (finding_id,),
                )
                gaps: list[ProofGap] = []
                for r in cur.fetchall():
                    gaps.append(
                        ProofGap(
                            gap_id=r["gap_id"],
                            finding_id=r["finding_id"],
                            target_symbol=r["target_symbol"] or "",
                            description=r["description"],
                            rationale=r["rationale"] or "",
                            resolution_criteria=r["resolution_criteria"] or "",
                            status=ProofGapStatus(r["status"])
                            if r["status"] in [s.value for s in ProofGapStatus]
                            else r["status"],
                            supporting_evidence=json.loads(r["supporting_evidence_json"]),
                        )
                    )
                return gaps
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error fetching proof gaps for {finding_id}: {error}"
            ) from error

    def save_proof_gap(self, proof_gap: ProofGap) -> None:
        """Persist or update a proof gap."""
        try:
            with self._connection() as conn, conn:
                gap_id = proof_gap.ensure_id()
                status_str = (
                    proof_gap.status.value
                    if isinstance(proof_gap.status, ProofGapStatus)
                    else str(proof_gap.status)
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO proof_gaps
                    (gap_id, finding_id, target_symbol, description, rationale, resolution_criteria, status, supporting_evidence_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'));
                    """,
                    (
                        gap_id,
                        proof_gap.finding_id,
                        proof_gap.target_symbol,
                        proof_gap.description,
                        proof_gap.rationale,
                        proof_gap.resolution_criteria,
                        status_str,
                        json.dumps(proof_gap.supporting_evidence),
                    ),
                )
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error saving proof gap {proof_gap.gap_id}: {error}"
            ) from error

    def update_proof_gap_status(self, gap_id: str, status: ProofGapStatus | str) -> bool:
        """Update resolution status of a proof gap."""
        status_val = status.value if isinstance(status, ProofGapStatus) else str(status)
        try:
            with self._connection() as conn, conn:
                cur = conn.execute(
                    "UPDATE proof_gaps SET status = ? WHERE gap_id = ?;",
                    (status_val, gap_id),
                )
                return cur.rowcount > 0
        except sqlite3.Error as error:
            raise StorageError(f"Database error updating proof gap {gap_id}: {error}") from error

    def get_adjudications(self, finding_id: str) -> list[dict[str, Any]]:
        """Fetch adjudication audit history for a finding."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM adjudications WHERE finding_id = ? ORDER BY timestamp DESC;",
                    (finding_id,),
                )
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error fetching adjudications for {finding_id}: {error}"
            ) from error

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

                graph = SemanticProgramGraph(
                    repository_root=repo_path, source_revision=source_revision
                )
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

    def save_hypothesis(
        self, hypothesis: InvestigationHypothesis, scan_id: str, repo_path: str
    ) -> None:
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
                return [
                    InvestigationHypothesis.model_validate_json(row["full_json"])
                    for row in cur.fetchall()
                ]
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

    def load_repository_memory(
        self, repo_path: str, source_revision: str
    ) -> InvestigationMemoryRecord | None:
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

    def load_latest_repository_memory(self, repo_path: str) -> InvestigationMemoryRecord | None:
        """Load the most recent persistent repository memory for a repository path."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM repository_memory WHERE repo_path = ? ORDER BY updated_at DESC LIMIT 1;",
                    (repo_path,),
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
            raise StorageError(
                f"Database error loading latest repository memory: {error}"
            ) from error

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

    def save_coordinator_run(self, run_result: Any) -> None:
        """Persist coordinator execution run, packets, worker executions, and reducer decisions."""
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """INSERT OR REPLACE INTO investigation_runs (
                        run_id, scan_id, repository_path, source_revision, mode,
                        max_concurrent_workers, packets_count, workers_count,
                        input_tokens, output_tokens, cached_input_tokens, total_tokens,
                        security_score, duration_seconds, is_sealed, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                    (
                        run_result.run_id,
                        run_result.scan_id,
                        run_result.repository_path,
                        run_result.source_revision,
                        run_result.mode,
                        run_result.max_concurrent_workers,
                        len(run_result.packets),
                        len(run_result.worker_outputs),
                        run_result.input_tokens,
                        run_result.output_tokens,
                        run_result.cached_input_tokens,
                        run_result.total_tokens,
                        run_result.finalization_report.overall_security_score,
                        run_result.duration_seconds,
                        1 if run_result.finalization_report.is_sealed else 0,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

                for pkt in run_result.packets:
                    conn.execute(
                        """INSERT OR REPLACE INTO investigation_packets (
                            packet_id, run_id, title, focus_category, priority, status,
                            target_symbols_json, entrypoints_json, sinks_json, file_paths_json,
                            assigned_worker_id, retry_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                        (
                            pkt.packet_id,
                            run_result.run_id,
                            pkt.title,
                            pkt.focus_category,
                            pkt.priority,
                            pkt.status.value if hasattr(pkt.status, "value") else str(pkt.status),
                            json.dumps(pkt.target_symbols),
                            json.dumps(pkt.entrypoint_ids),
                            json.dumps(pkt.sink_ids),
                            json.dumps(pkt.file_paths),
                            pkt.assigned_worker_id,
                            pkt.retry_count,
                        ),
                    )

                for w in run_result.worker_outputs:
                    conn.execute(
                        """INSERT OR REPLACE INTO worker_executions (
                            worker_id, run_id, packet_id, role,
                            input_tokens, output_tokens, cached_input_tokens, total_tokens,
                            duration_seconds, is_successful, error_message, executed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                        (
                            w.worker_id,
                            run_result.run_id,
                            w.packet_id,
                            w.worker_role.value
                            if hasattr(w.worker_role, "value")
                            else str(w.worker_role),
                            w.input_tokens,
                            w.output_tokens,
                            w.cached_input_tokens,
                            w.total_tokens,
                            w.duration_seconds,
                            1 if w.is_successful else 0,
                            w.error_message,
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )

                for dec in run_result.reducer_result.audit_records:
                    conn.execute(
                        """INSERT OR REPLACE INTO reducer_decisions (
                            decision_id, run_id, finding_id, outcome, reason,
                            contributing_workers_json, decided_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);""",
                        (
                            dec.decision_id,
                            run_result.run_id,
                            dec.finding_id,
                            dec.outcome,
                            dec.reason,
                            json.dumps(dec.contributing_workers),
                            dec.decided_at,
                        ),
                    )
        except sqlite3.Error as error:
            raise StorageError(f"Database error persisting coordinator run: {error}") from error

    def get_coordinator_run(self, run_id: str) -> dict[str, Any] | None:
        """Retrieve investigation run summary by run_id."""
        try:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM investigation_runs WHERE run_id = ?;", (run_id,))
                row = cur.fetchone()
                return dict(row) if row else None
        except sqlite3.Error as error:
            raise StorageError(f"Database error retrieving coordinator run: {error}") from error

    def list_coordinator_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent investigation runs ordered by created_at DESC."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM investigation_runs ORDER BY created_at DESC LIMIT ?;", (limit,)
                )
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(f"Database error listing coordinator runs: {error}") from error

    def get_investigation_packets(self, run_id: str) -> list[dict[str, Any]]:
        """Retrieve packets for an investigation run."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM investigation_packets WHERE run_id = ? ORDER BY priority DESC;",
                    (run_id,),
                )
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error retrieving investigation packets: {error}"
            ) from error

    def get_worker_executions(self, run_id: str) -> list[dict[str, Any]]:
        """Retrieve worker execution logs for an investigation run."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM worker_executions WHERE run_id = ? ORDER BY executed_at ASC;",
                    (run_id,),
                )
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(f"Database error retrieving worker executions: {error}") from error

    def get_reducer_decisions(self, run_id: str) -> list[dict[str, Any]]:
        """Retrieve reducer decisions for an investigation run."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM reducer_decisions WHERE run_id = ? ORDER BY decided_at ASC;",
                    (run_id,),
                )
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(f"Database error retrieving reducer decisions: {error}") from error

    # Phase 4 Finding Intelligence Workbench & Lifecycle Persistence
    def save_finding_version(
        self,
        version_id: str,
        finding_id: str,
        version_number: int,
        lifecycle_state: str,
        confidence: str,
        severity: str,
        semantic_identity: dict[str, Any] | None = None,
        snapshot: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> None:
        """Persist a snapshot version of a finding."""
        created = created_at or datetime.now(timezone.utc).isoformat()
        sem_json = json.dumps(semantic_identity) if semantic_identity is not None else "{}"
        snap_json = json.dumps(snapshot) if snapshot is not None else "{}"
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO finding_versions
                    (version_id, finding_id, version_number, lifecycle_state, confidence, severity, semantic_identity_json, snapshot_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        version_id,
                        finding_id,
                        version_number,
                        lifecycle_state,
                        confidence,
                        severity,
                        sem_json,
                        snap_json,
                        created,
                    ),
                )
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error saving finding version {version_id}: {error}"
            ) from error

    def get_finding_versions(self, finding_id: str) -> list[dict[str, Any]]:
        """Retrieve all versions of a finding ordered by version_number ASC."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM finding_versions WHERE finding_id = ? ORDER BY version_number ASC;",
                    (finding_id,),
                )
                rows = []
                for r in cur.fetchall():
                    d = dict(r)
                    d["semantic_identity"] = json.loads(d.get("semantic_identity_json", "{}"))
                    d["snapshot"] = json.loads(d.get("snapshot_json", "{}"))
                    rows.append(d)
                return rows
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error fetching finding versions for {finding_id}: {error}"
            ) from error

    def record_lifecycle_transition(
        self,
        transition_id: str,
        finding_id: str,
        from_state: str,
        to_state: str,
        trigger_reason: str,
        actor_or_component: str = "orchestrator",
        timestamp: str | None = None,
    ) -> None:
        """Record an explicit lifecycle state transition and atomically update the canonical finding."""
        to_clean = to_state.strip().lower()
        if to_clean not in VALID_LIFECYCLE_STATES:
            raise ValueError(
                f"Invalid target lifecycle state: '{to_state}'. Valid states: {sorted(VALID_LIFECYCLE_STATES)}"
            )

        ts = timestamp or datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO lifecycle_transitions
                    (transition_id, finding_id, from_state, to_state, trigger_reason, actor_or_component, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        transition_id,
                        finding_id,
                        from_state,
                        to_clean,
                        trigger_reason,
                        actor_or_component,
                        ts,
                    ),
                )
                cur = conn.execute(
                    "SELECT full_json FROM findings WHERE finding_id = ?;", (finding_id,)
                )
                row = cur.fetchone()
                if row:
                    try:
                        raw_json = row["full_json"]
                        data = json.loads(raw_json) if raw_json else {}
                        data["lifecycle_state"] = to_clean
                        updated_json = json.dumps(data)
                    except Exception:
                        updated_json = row["full_json"]
                    conn.execute(
                        "UPDATE findings SET lifecycle_state = ?, full_json = ? WHERE finding_id = ?;",
                        (to_clean, updated_json, finding_id),
                    )
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error recording lifecycle transition for {finding_id}: {error}"
            ) from error

    def get_lifecycle_transitions(self, finding_id: str) -> list[dict[str, Any]]:
        """Fetch audit log of lifecycle state transitions for a finding."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM lifecycle_transitions WHERE finding_id = ? ORDER BY timestamp ASC;",
                    (finding_id,),
                )
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error fetching lifecycle transitions for {finding_id}: {error}"
            ) from error

    def save_semantic_merge(
        self,
        merge_id: str,
        primary_finding_id: str,
        secondary_finding_id: str,
        decision_outcome: str,
        equivalence_confidence: float,
        merge_rationale: str,
        evidence_ids_merged: list[str] | None = None,
        contributing_workers: list[str] | None = None,
        merged_at: str | None = None,
    ) -> None:
        """Persist an audit record of a semantic deduplication merge."""
        ev_json = json.dumps(evidence_ids_merged or [])
        workers_json = json.dumps(contributing_workers or [])
        ts = merged_at or datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO semantic_merges
                    (merge_id, primary_finding_id, secondary_finding_id, decision_outcome, equivalence_confidence, merge_rationale, evidence_ids_merged_json, contributing_workers_json, merged_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        merge_id,
                        primary_finding_id,
                        secondary_finding_id,
                        decision_outcome,
                        equivalence_confidence,
                        merge_rationale,
                        ev_json,
                        workers_json,
                        ts,
                    ),
                )
                # Atomically ensure secondary finding lifecycle_state is marked as DUPLICATE
                cur = conn.execute(
                    "SELECT full_json FROM findings WHERE finding_id = ?;", (secondary_finding_id,)
                )
                row = cur.fetchone()
                if row:
                    try:
                        raw_json = row["full_json"]
                        data = json.loads(raw_json) if raw_json else {}
                        data["lifecycle_state"] = "duplicate"
                        data.setdefault("metadata", {})["primary_finding_id"] = primary_finding_id
                        data["metadata"]["duplicate_of"] = primary_finding_id
                        data["metadata"]["merge_id"] = merge_id
                        updated_json = json.dumps(data)
                    except Exception:
                        updated_json = row["full_json"]
                    conn.execute(
                        "UPDATE findings SET lifecycle_state = 'duplicate', full_json = ? WHERE finding_id = ?;",
                        (updated_json, secondary_finding_id),
                    )
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error saving semantic merge record {merge_id}: {error}"
            ) from error

    def get_semantic_merges(self, primary_finding_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve semantic merge records, optionally filtered by primary finding ID."""
        try:
            with self._connection() as conn:
                if primary_finding_id:
                    cur = conn.execute(
                        "SELECT * FROM semantic_merges WHERE primary_finding_id = ? ORDER BY merged_at ASC;",
                        (primary_finding_id,),
                    )
                else:
                    cur = conn.execute("SELECT * FROM semantic_merges ORDER BY merged_at ASC;")
                rows = []
                for r in cur.fetchall():
                    d = dict(r)
                    d["evidence_ids_merged"] = json.loads(d.get("evidence_ids_merged_json", "[]"))
                    d["contributing_workers"] = json.loads(d.get("contributing_workers_json", "[]"))
                    rows.append(d)
                return rows
        except sqlite3.Error as error:
            raise StorageError(f"Database error fetching semantic merges: {error}") from error

    def record_provider_usage(
        self,
        usage_id: str,
        run_id: str,
        worker_id: str,
        provider_name: str,
        model_name: str,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
        total_tokens: int,
        estimated_cost_usd: float = 0.0,
        timestamp: str | None = None,
    ) -> None:
        """Persist fine-grained provider token consumption and cost metrics."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        try:
            with self._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO provider_usage
                    (usage_id, run_id, worker_id, provider_name, model_name, input_tokens, cached_input_tokens, output_tokens, total_tokens, estimated_cost_usd, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        usage_id,
                        run_id,
                        worker_id,
                        provider_name,
                        model_name,
                        input_tokens,
                        cached_input_tokens,
                        output_tokens,
                        total_tokens,
                        estimated_cost_usd,
                        ts,
                    ),
                )
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error recording provider usage {usage_id}: {error}"
            ) from error

    def get_provider_usage(self, run_id: str) -> list[dict[str, Any]]:
        """Fetch all provider usage and token consumption records for a run."""
        try:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM provider_usage WHERE run_id = ? ORDER BY timestamp ASC;",
                    (run_id,),
                )
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as error:
            raise StorageError(
                f"Database error fetching provider usage for run {run_id}: {error}"
            ) from error
