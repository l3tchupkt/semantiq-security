"""Payment processing service for secure order management."""

from __future__ import annotations

from tests.fixtures.ecommerce_multistep_safe.models import Order, OrderStatus


class PaymentService:
    def __init__(self) -> None:
        self.processed_payments: dict[str, str] = {}

    def process_payment(self, order: Order, payment_token: str) -> bool:
        if not payment_token.startswith("tok_"):
            return False

        order.payment_reference = f"ref_{order.order_id}"
        order.status = OrderStatus.PAID
        self.processed_payments[order.order_id] = order.payment_reference
        return True
