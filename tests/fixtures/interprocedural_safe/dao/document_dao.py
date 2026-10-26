"""Safe document DAO enforcing genuine tenant isolation via authenticated session."""

import sqlite3

session = {"tenant_id": "tenant_alpha_99"}


def query_document_by_id(doc_id: str):
    """Retrieve document scoped to active tenant context."""
    conn = sqlite3.connect("documents.db")
    cursor = conn.cursor()
    active_tenant = session.get("tenant_id")
    cursor.execute(
        "SELECT * FROM documents WHERE id = ? AND tenant_id = ?",
        (doc_id, active_tenant),
    )
    return cursor.fetchall()
