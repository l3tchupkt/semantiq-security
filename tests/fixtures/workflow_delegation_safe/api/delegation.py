"""REST API endpoints for workflow delegation management."""

from typing import Any

from services.task_coordinator import TaskCoordinator

coordinator = TaskCoordinator()


def require_auth(fn):
    """Authentication middleware decorator."""
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


class DelegationRouter:
    """Handles HTTP routes for worker task delegation."""

    def _can_delegate_scope(self, current_user: dict[str, Any], requested_scope: str) -> bool:
        """Enforces least-privilege delegation invariant: callers cannot delegate scopes exceeding their own."""
        caller_roles = current_user.get("roles", ["standard"])
        if requested_scope == "admin" and "admin" not in caller_roles:
            return False
        return requested_scope in caller_roles

    @require_auth
    def delegate_task(self, request_data: dict[str, Any], current_user: dict[str, Any]) -> dict[str, Any]:
        """Allows worker to delegate subtask execution authority to another user or agent."""
        caller_id = current_user.get("user_id", "anonymous")
        delegatee_id = request_data.get("delegatee_id", "")
        requested_scope = request_data.get("requested_role_scope", "standard")

        # Mitigating Counterevidence: Authority boundary check prevents scope elevation
        if not self._can_delegate_scope(current_user, requested_scope):
            return {
                "status": "denied",
                "error": "Caller lacks authority to delegate the requested role scope",
            }

        token = coordinator.issue_delegation_token(
            delegator_id=caller_id,
            delegatee_id=delegatee_id,
            requested_scope=requested_scope,
        )
        return {
            "status": "granted",
            "delegation_token": token,
            "granted_scope": requested_scope,
        }

    @require_auth
    def execute_delegated(self, request_data: dict[str, Any], current_user: dict[str, Any]) -> dict[str, Any]:
        """Executes task operations authorized by delegation token."""
        token = request_data.get("delegation_token", "")
        action = request_data.get("action", {})

        result = coordinator.execute_delegated_task(token, action)
        return result
