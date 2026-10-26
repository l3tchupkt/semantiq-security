"""Document DAO executing query without tenant isolation filter."""

import sqlite3


def query_document_by_id(doc_id: str):
    """Retrieve document by object id without tenant scoping filter."""
    conn = sqlite3.connect("documents.db")
    cursor = conn.cursor()
    # Missing tenant isolation filter
    sql = f"SELECT * FROM documents WHERE id = '{doc_id}'"
    cursor.execute(sql)
    return cursor.fetchall()
