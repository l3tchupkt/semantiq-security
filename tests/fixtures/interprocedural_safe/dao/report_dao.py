"""Safe report DAO using parameterized SQL query."""

import sqlite3


def run_report_query(report_id: int):
    conn = sqlite3.connect("reports.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    return cursor.fetchall()
