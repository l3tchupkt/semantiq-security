"""Report DAO executing SQL query for report."""

import sqlite3


def run_report_query(report_id: str | int):
    """Execute SQL query using provided report identifier."""
    conn = sqlite3.connect("reports.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM reports WHERE id = {report_id}")
    return cursor.fetchall()
