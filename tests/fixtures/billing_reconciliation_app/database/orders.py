"""Orders database access module."""
from __future__ import annotations

from typing import Any

ORDERS_DB: dict[str, dict[str, Any]] = {
    "ord_101": {"order_id": "ord_101", "user_id": "usr_99", "amount": 250.0, "status": "COMPLETED"},
    "ord_102": {"order_id": "ord_102", "user_id": "usr_42", "amount": 100.0, "status": "COMPLETED"},
}


def get_order_by_id(order_id: str) -> dict[str, Any] | None:
    """Retrieve order record by ID."""
    return ORDERS_DB.get(order_id)
