"""Refund request API endpoint with atomic reservation guard."""
from __future__ import annotations

from typing import Any

from database.orders import claim_atomic_refund_lock, get_order_by_id
from services.refund_queue import dispatch_refund_job


def jwt_required(func: Any) -> Any:
    """Simulate JWT authentication decorator."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)
    return wrapper


@jwt_required
def request_refund(order_id: str, caller_id: str, amount: float) -> dict[str, Any]:
    """Accept and enqueue a refund request with atomic reservation locking."""
    order = get_order_by_id(order_id)
    if not order:
        return {"error": "Order not found", "status": 404}

    if order.get("user_id") != caller_id:
        return {"error": "Unauthorized order access", "status": 403}

    if amount > order.get("amount", 0.0):
        return {"error": "Amount exceeds order total", "status": 400}

    # MITIGATION: Atomic state lock acquired prior to queue dispatch
    if not claim_atomic_refund_lock(order_id):
        return {"error": "Conflict: Refund already in progress or completed", "status": 409}

    job_id = dispatch_refund_job(order_id=order_id, amount=amount, recipient=caller_id)
    return {"status": "accepted", "job_id": job_id, "state": "RESERVED"}
