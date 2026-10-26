"""Safe multi-tenant document retrieval with tenant scoping."""

import sqlite3

session = {"tenant_id": "tenant_123"}


def safe_get_tenant_document(doc_id: str) -> list:
    """Safely fetch document scoped to current tenant_id with parameterized query."""
    conn = sqlite3.connect("tenant.db")
    cursor = conn.cursor()
    # Explicit tenant isolation and parameterization
    current_tenant = session.get("tenant_id")
    cursor.execute(
        "SELECT * FROM documents WHERE id = ? AND tenant_id = ?",
        (doc_id, current_tenant),
    )
    return cursor.fetchall()
