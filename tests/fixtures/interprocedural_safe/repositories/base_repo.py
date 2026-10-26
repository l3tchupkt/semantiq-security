"""Safe base repository using parameterized query."""

import sqlite3


class BaseRepository:
    def execute_parameterized_sql(self, sql: str, params: tuple):
        """Execute parameterized query safely."""
        conn = sqlite3.connect("custom.db")
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return cursor.fetchall()
