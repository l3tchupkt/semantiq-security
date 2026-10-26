"""Database abstraction layer for multitenant fixture."""

import sqlite3


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    return conn


def execute_query(cursor: sqlite3.Cursor, query: str) -> list:
    cursor.execute(query)
    return cursor.fetchall()
