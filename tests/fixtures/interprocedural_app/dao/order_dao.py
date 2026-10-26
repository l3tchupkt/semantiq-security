"""Database access layer executing query for orders."""

import sqlite3


def fetch_orders_by_title(query: str):
    """Execute raw SQL query with unvalidated parameter (SQL Injection)."""
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    sql = f"SELECT * FROM orders WHERE title = '{query}'"
    cursor.execute(sql)
    return cursor.fetchall()
