"""Order fulfillment and payment state transition service."""

from dataclasses import dataclass


@dataclass
class Order:
    order_id: str
    status: str
    amount: float


def fulfill_order(order_id: str) -> Order:
    """Fulfill order directly without checking payment completion invariant.

    VULNERABILITY: SQ-PY-018 Business Logic Flaw / State Transition Violation
    """
    order = Order(order_id=order_id, status="PENDING", amount=99.99)
    # Direct transition to FULFILLED without checking if payment succeeded
    order.status = "FULFILLED"
    return order
