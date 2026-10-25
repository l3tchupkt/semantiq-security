"""Safe database helper module."""

import sqlite3


def execute_safe_query(cursor: sqlite3.Cursor, sql: str, params: tuple) -> list:
    """Helper executing parameterized query."""
    cursor.execute(sql, params)
    return cursor.fetchall()
