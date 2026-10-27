"""External payment gateway interface."""
from __future__ import annotations

import uuid
from typing import Any


def execute_gateway_refund(recipient: str, amount: float) -> dict[str, Any]:
    """Execute irrevocable external credit card refund."""
    return {"status": "success", "tx_id": f"tx_{uuid.uuid4().hex[:10]}", "amount": amount}
