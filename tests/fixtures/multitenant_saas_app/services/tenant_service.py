"""Multi-tenant document management service."""

import sqlite3


def get_tenant_document(doc_id: str) -> list:
    """Retrieve document without scoping query to active tenant_id or user.

    VULNERABILITY: SQ-PY-015 Cross-Tenant Data Leakage (queries documents without tenant_id filter)
    VULNERABILITY: SQ-PY-002 SQL Injection
    """
    conn = sqlite3.connect("tenant.db")
    cursor = conn.cursor()
    # Missing tenant isolation filter
    query = f"SELECT * FROM documents WHERE id = '{doc_id}'"
    cursor.execute(query)
    return cursor.fetchall()
