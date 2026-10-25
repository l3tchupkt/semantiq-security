"""SQLite persistence layer for scans, findings, threat models, and patches."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from semantiq.exceptions import StorageError
from semantiq.models import (
    Finding,
    ScanResult,
)

SCHEMA_V1 = """
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
            conn.executescript(SCHEMA_V1)
            cur = conn.execute("SELECT version FROM schema_version;")
            row = cur.fetchone()
            if not row:
                conn.execute("INSERT INTO schema_version (version) VALUES (1);")
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
