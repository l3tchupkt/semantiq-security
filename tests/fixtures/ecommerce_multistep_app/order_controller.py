"""Order HTTP API controller with multi-step workflows."""

from __future__ import annotations

from tests.fixtures.ecommerce_multistep_app.models import Order
from tests.fixtures.ecommerce_multistep_app.payment_service import PaymentService
from tests.fixtures.ecommerce_multistep_app.shipping_service import ShippingService

# In-memory repository
ORDERS_DB: dict[str, Order] = {}
shipping_svc = ShippingService()
payment_svc = PaymentService()


def app_route(path: str, methods: list[str] | None = None):
    def decorator(fn):
        fn.route_path = path
        fn.http_methods = methods or ["GET"]
        return fn
    return decorator


@app_route("/api/orders/create", methods=["POST"])
def create_order(customer_id: str, amount: float) -> dict[str, str]:
    order_id = f"ord_{len(ORDERS_DB) + 1}"
    order = Order(order_id=order_id, customer_id=customer_id, total_amount=amount)
    ORDERS_DB[order_id] = order
    return {"order_id": order_id, "status": "CREATED"}


@app_route("/api/orders/pay", methods=["POST"])
def pay_order(order_id: str, token: str) -> dict[str, str]:
    order = ORDERS_DB.get(order_id)
    if not order:
        return {"error": "not_found"}
    success = payment_svc.process_payment(order, token)
    return {"order_id": order_id, "paid": str(success)}


@app_route("/api/orders/fulfill", methods=["POST"])
def fulfill_order(order_id: str) -> dict[str, str]:
    # Multi-step state machine vulnerability:
    # Directly dispatches and sets order.status = "FULFILLED" without checking payment!
    order = ORDERS_DB.get(order_id)
    if not order:
        return {"error": "not_found"}

    result = shipping_svc.dispatch_order(order)
    return result
