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

    @require_auth
    def delegate_task(self, request_data: dict[str, Any], current_user: dict[str, Any]) -> dict[str, Any]:
        """Allows worker to delegate subtask execution authority to another user or agent.

        Request parameters:
            delegatee_id: string ID of the recipient
            requested_role_scope: role permission scope granted ('standard', 'analyst', 'admin')
        """
        caller_id = current_user.get("user_id", "anonymous")
        delegatee_id = request_data.get("delegatee_id", "")
        requested_scope = request_data.get("requested_role_scope", "standard")

        # Flaw: No check verifying that caller possesses the requested_role_scope.
        # Any authenticated user can issue delegation tokens granting 'admin' role scope.
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
