"""Coordinates task delegation tokens and dispatches execution."""

import hashlib
import hmac
import json
import time
from typing import Any

from services.execution_engine import ExecutionEngine

SECRET_KEY = b"internal-delegation-service-key-32b"


class TaskCoordinator:
    """Issues and validates delegation tokens for subtask execution."""

    def __init__(self) -> None:
        self.engine = ExecutionEngine()

    def issue_delegation_token(
        self,
        delegator_id: str,
        delegatee_id: str,
        requested_scope: str,
    ) -> str:
        """Constructs and signs a delegation grant token."""
        payload = {
            "delegator": delegator_id,
            "delegatee": delegatee_id,
            "role_scope": requested_scope,
            "issued_at": time.time(),
        }
        encoded = json.dumps(payload, sort_keys=True)
        sig = hmac.new(SECRET_KEY, encoded.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{encoded}|{sig}"

    def execute_delegated_task(
        self,
        delegation_token: str,
        action: dict[str, Any],
    ) -> dict[str, Any]:
        """Validates token authenticity and executes task with delegated scope."""
        parts = delegation_token.split("|")
        if len(parts) != 2:
            return {"status": "error", "message": "Malformed token format"}

        encoded, signature = parts
        expected_sig = hmac.new(SECRET_KEY, encoded.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return {"status": "error", "message": "Invalid token signature"}

        payload = json.loads(encoded)
        role_scope = payload.get("role_scope", "standard")

        # Dispatches to privileged execution engine using token's role_scope
        return self.engine.run_privileged_task(role_scope, action)
