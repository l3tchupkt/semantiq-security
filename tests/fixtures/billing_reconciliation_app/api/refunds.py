"""Refund request API endpoint."""
from __future__ import annotations

from typing import Any

from database.orders import get_order_by_id
from services.refund_queue import dispatch_refund_job


def jwt_required(func: Any) -> Any:
    """Simulate JWT authentication decorator."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)
    return wrapper


@jwt_required
def request_refund(order_id: str, caller_id: str, amount: float) -> dict[str, Any]:
    """Accept and enqueue a refund request.

    VULNERABILITY: Does not establish an atomic lock or update order status to RESERVED
    prior to queue dispatch, allowing concurrent requests to duplicate refunds.
    """
    order = get_order_by_id(order_id)
    if not order:
        return {"error": "Order not found", "status": 404}

    if order.get("user_id") != caller_id:
        return {"error": "Unauthorized order access", "status": 403}

    if amount > order.get("amount", 0.0):
        return {"error": "Amount exceeds order total", "status": 400}

    # Crosses trust boundary: asynchronous worker execution without atomic reservation
    job_id = dispatch_refund_job(order_id=order_id, amount=amount, recipient=caller_id)
    return {"status": "accepted", "job_id": job_id, "state": "PENDING"}
