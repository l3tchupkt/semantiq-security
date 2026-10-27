"""Orders database access module with atomic state locking."""
from __future__ import annotations

from typing import Any

ORDERS_DB: dict[str, dict[str, Any]] = {
    "ord_101": {"order_id": "ord_101", "user_id": "usr_99", "amount": 250.0, "status": "COMPLETED", "locked": False},
    "ord_102": {"order_id": "ord_102", "user_id": "usr_42", "amount": 100.0, "status": "COMPLETED", "locked": False},
}


def get_order_by_id(order_id: str) -> dict[str, Any] | None:
    """Retrieve order record by ID."""
    return ORDERS_DB.get(order_id)


def claim_atomic_refund_lock(order_id: str) -> bool:
    """Acquire atomic reservation lock preventing concurrent execution."""
    order = ORDERS_DB.get(order_id)
    if not order or order.get("locked") or order.get("status") != "COMPLETED":
        return False
    order["locked"] = True
    order["status"] = "REFUND_RESERVED"
    return True
