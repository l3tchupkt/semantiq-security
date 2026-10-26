"""Safe database helper with parameterization."""

import sqlite3


def get_db_connection() -> sqlite3.Connection:
    return sqlite3.connect(":memory:")


def execute_parameterized_query(cursor: sqlite3.Cursor, query: str, params: tuple) -> list:
    cursor.execute(query, params)
    return cursor.fetchall()
