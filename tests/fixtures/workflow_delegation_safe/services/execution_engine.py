"""Task execution engine executing tasks based on granted delegation scopes."""

from typing import Any

from database.jobs import JobDatabase

db = JobDatabase()


class ExecutionEngine:
    """Executes background jobs, workflows, and administrative actions."""

    def __init__(self) -> None:
        self.db = db

    def run_privileged_task(self, role_scope: str, action: dict[str, Any]) -> dict[str, Any]:
        """Executes operations according to delegated role scope."""
        op_type = action.get("operation", "standard_task")

        if role_scope == "admin":
            if op_type == "purge_audit":
                purged = self.db.purge_all_audit_logs(target_scope="global")
                return {"status": "success", "purged_records": purged}
            elif op_type == "override_config":
                updated = self.db.override_system_configuration(action.get("settings", {}))
                return {"status": "success", "updated": updated}

        # Non-admin operations
        job_id = action.get("job_id", "default_task")
        self.db.record_job(job_id, action)
        return {"status": "success", "executed_job": job_id}
