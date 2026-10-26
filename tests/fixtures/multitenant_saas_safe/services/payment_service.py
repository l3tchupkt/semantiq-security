"""Safe order fulfillment enforcing state machine preconditions."""

from dataclasses import dataclass


@dataclass
class Order:
    order_id: str
    status: str
    amount: float


def safe_fulfill_order(order_id: str) -> Order:
    """Fulfill order only after checking that payment status is verified PAID."""
    order = Order(order_id=order_id, status="PENDING", amount=99.99)

    # Validate state machine invariant
    if order.status != "PAID":
        raise ValueError(f"Cannot fulfill order {order_id} in state {order.status}")

    order.status = "FULFILLED"
    return order
