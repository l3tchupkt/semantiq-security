"""Safe order DAO using parameterized query."""

import sqlite3


def fetch_orders_by_title(query: str):
    """Execute safe parameterized SQL query."""
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE title = ?", (query,))
    return cursor.fetchall()
