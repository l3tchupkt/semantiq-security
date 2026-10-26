"""Base repository defining common database operations."""

import sqlite3


class BaseRepository:
    def execute_raw_sql(self, sql: str):
        """Execute SQL statement directly."""
        conn = sqlite3.connect("custom.db")
        cursor = conn.cursor()
        cursor.execute(sql)
        return cursor.fetchall()
