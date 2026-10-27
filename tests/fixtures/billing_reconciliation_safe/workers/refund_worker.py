"""Background worker that executes external refunds and ledger updates."""
from __future__ import annotations

from typing import Any

from models.ledger import record_ledger_deduction
from services.payment_gateway import execute_gateway_refund


def process_refund_worker(job: dict[str, Any]) -> dict[str, Any]:
    """Execute refund against external payment gateway."""
    order_id = job["order_id"]
    amount = float(job["amount"])
    recipient = job["recipient"]

    gateway_resp = execute_gateway_refund(recipient, amount)
    record_ledger_deduction(order_id, amount)
    return {"status": "refunded", "tx_id": gateway_resp.get("tx_id")}
