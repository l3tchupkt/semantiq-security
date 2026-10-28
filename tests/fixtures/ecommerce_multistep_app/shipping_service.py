"""Shipping and fulfillment service."""

from __future__ import annotations

from tests.fixtures.ecommerce_multistep_app.models import Order, OrderStatus


class ShippingService:
    def __init__(self) -> None:
        self.dispatched_orders: list[str] = []

    def dispatch_order(self, order: Order, tracking_carrier: str = "DHL") -> dict[str, str]:
        order.status = OrderStatus.FULFILLED
        tracking_number = f"TRK-{order.order_id}-{tracking_carrier}"
        self.dispatched_orders.append(order.order_id)
        return {"order_id": order.order_id, "tracking": tracking_number, "status": "FULFILLED"}
