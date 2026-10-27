"""Financial ledger audit record."""
from __future__ import annotations

from typing import Any

LEDGER_RECORDS: list[dict[str, Any]] = []


def record_ledger_deduction(order_id: str, amount: float) -> None:
    """Record refund deduction in ledger."""
    LEDGER_RECORDS.append({"order_id": order_id, "deduction": amount})
