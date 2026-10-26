"""Secure E-commerce multi-step order models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class OrderStatus(str, Enum):
    CREATED = "CREATED"
    PENDING_PAYMENT = "PENDING_PAYMENT"
    PAID = "PAID"
    FULFILLED = "FULFILLED"
    SHIPPED = "SHIPPED"
    CANCELLED = "CANCELLED"


@dataclass
class Order:
    order_id: str
    customer_id: str
    total_amount: float
    items: list[dict[str, str]] = field(default_factory=list)
    status: OrderStatus = OrderStatus.CREATED
    payment_reference: str | None = None

    @property
    def is_paid(self) -> bool:
        return self.status == OrderStatus.PAID
