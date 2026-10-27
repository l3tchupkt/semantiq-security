"""Asynchronous refund task dispatch queue."""
from __future__ import annotations

import uuid
from typing import Any

PENDING_QUEUE: list[dict[str, Any]] = []


def dispatch_refund_job(order_id: str, amount: float, recipient: str) -> str:
    """Enqueue asynchronous refund job across boundary."""
    job_id = f"job_ref_{uuid.uuid4().hex[:8]}"
    payload = {"job_id": job_id, "order_id": order_id, "amount": amount, "recipient": recipient}
    PENDING_QUEUE.append(payload)
    return job_id
