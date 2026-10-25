"""Database helper module for vulnerable test application."""

import sqlite3


def execute_raw_query(cursor: sqlite3.Cursor, sql: str) -> list:
    """Helper executing unparameterized SQL query."""
    # VULNERABILITY: Raw database execution on passed parameter
    cursor.execute(sql)
    return cursor.fetchall()
