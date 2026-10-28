"""Isolated Ground Truth Catalog for Beyond-Heuristics Security Evaluations.

NEVER imported into live investigator prompts, tool implementations, or discovery engines.
Used exclusively by the post-investigation FindingAdjudicator to independently evaluate findings.
"""

from __future__ import annotations

from pathlib import Path

from evals.beyond_heuristics.adjudicator import CaseGroundTruth

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

GROUND_TRUTH_CATALOG: dict[str, CaseGroundTruth] = {
    "case_1_delegation_scope": CaseGroundTruth(
        case_id="case_1_delegation_scope",
        title="Cross-Module Privilege Escalation via Unverified Delegation Scope",
        primary_flaw_file="api/delegation.py",
        affected_modules=[
            "api/delegation.py",
            "services/task_coordinator.py",
            "services/execution_engine.py",
            "database/jobs.py",
        ],
        valid_entry_points=[
            "delegate_task",
            "DelegationRouter.delegate_task",
            "/api/v1/delegation/delegate",
            "/api/delegation/delegate",
        ],
        required_root_cause_concepts=[
            ["scope", "role_scope", "requested_scope", "requested_role_scope"],
            ["caller", "authority", "permission", "verify", "check", "unverified"],
            ["delegat", "privilege", "token"],
        ],
        disqualifying_misattributions=[
            "sql injection",
            "sqli",
            "cross-site scripting",
            "xss",
            "csrf",
            "insecure direct object reference",
            "idor",
            "weak cryptography",
            "hardcoded secret",
            "path traversal",
        ],
        supported_impact=(
            "Vertical privilege escalation: An authenticated user can grant arbitrary role scopes "
            "('admin') via signed delegation tokens, enabling execution of privileged operations "
            "(purge_all_audit_logs, override_system_configuration) in ExecutionEngine."
        ),
        overstated_impact_patterns=[
            "remote code execution",
            "arbitrary shell execution",
            "kernel panic",
            "host compromise",
        ],
        safe_mitigation_checks=[
            "_can_delegate_scope",
            "caller_roles = current_user.get('roles'",
            "requested_scope in caller_roles",
        ],
    ),
    "case_2_reconciliation_race": CaseGroundTruth(
        case_id="case_2_reconciliation_race",
        title="Asynchronous Queue Double-Claim Invariant Violation",
        primary_flaw_file="api/refunds.py",
        affected_modules=[
            "api/refunds.py",
            "services/refund_queue.py",
            "workers/refund_worker.py",
            "services/payment_gateway.py",
            "models/ledger.py",
            "database/orders.py",
        ],
        valid_entry_points=[
            "request_refund",
            "/api/v1/refunds/request",
            "/api/refunds/request",
            "refunds.py",
        ],
        required_root_cause_concepts=[
            ["atomic", "lock", "reservation", "race", "concurren", "toctou"],
            ["queue", "dispatch", "enqueue", "asynchronous"],
            ["refund", "payout", "payment", "order"],
        ],
        disqualifying_misattributions=[
            "sql injection",
            "sqli",
            "cross-site scripting",
            "xss",
            "server-side request forgery",
            "ssrf",
            "path traversal",
            "command injection",
            "insecure deserialization",
        ],
        supported_impact=(
            "Financial loss via duplicate payouts: Concurrent refund requests for the same order "
            "are accepted and enqueued without an atomic reservation lock, triggering multiple "
            "external payment gateway transfers before ledger deduction occurs."
        ),
        overstated_impact_patterns=[
            "remote code execution",
            "arbitrary shell command execution",
            "privilege escalation",
            "database takeover",
        ],
        safe_mitigation_checks=[
            "claim_atomic_refund_lock",
            "order['locked'] = True",
            "order['status'] = 'REFUND_RESERVED'",
        ],
    ),
    "case_3_tenant_cache_poisoning": CaseGroundTruth(
        case_id="case_3_tenant_cache_poisoning",
        title="Cross-Tenant Workload Cache Poisoning via Unscoped Spec Hash",
        primary_flaw_file="services/compiler.py",
        affected_modules=[
            "api/workloads.py",
            "services/compiler.py",
            "services/cache.py",
            "services/scheduler.py",
            "database/tenants.py",
        ],
        valid_entry_points=[
            "submit_workload",
            "WorkloadRouter.submit_workload",
            "/api/v1/workloads/submit",
            "compile_workload_bundle",
        ],
        required_root_cause_concepts=[
            ["cache", "bundle_cache", "cache_key"],
            ["tenant", "isolation", "cross-tenant", "tenant_id", "unscoped"],
            ["spec_hash", "collision", "reuse", "poison"],
        ],
        disqualifying_misattributions=[
            "sql injection",
            "sqli",
            "cross-site scripting",
            "xss",
            "path traversal",
            "idor",
            "insecure deserialization",
            "hardcoded credentials",
        ],
        supported_impact=(
            "Cross-tenant execution bundle substitution: Workload bundles are cached using a global "
            "cache key 'bundle:{spec_hash}' without tenant scoping. Tenant A can pre-seed a spec_hash "
            "whose entrypoint and environment are reused when Tenant B executes the same workload."
        ),
        overstated_impact_patterns=[
            "remote code execution",
            "arbitrary host command injection",
            "host shell takeover",
            "container escape",
        ],
        safe_mitigation_checks=[
            "bundle:{tenant_id}:{spec_hash}",
            "cache_key = f\"bundle:{tenant_id}:{spec_hash}\"",
        ],
        hard_negative_disabled_paths=[
            "execute_debug_command",
            "DEBUG_FEATURE_ENABLED",
        ],
    ),
    "case_4_interprocedural_auth_divergence": CaseGroundTruth(
        case_id="case_4_interprocedural_auth_divergence",
        title="Multi-Tier Authorization Divergence via Public Bypass Controller",
        primary_flaw_file="web/public_controller.py",
        affected_modules=[
            "web/admin_controller.py",
            "web/public_controller.py",
            "services/user_service.py",
            "dao/document_dao.py",
            "web/document_controller.py",
            "services/document_service.py",
        ],
        valid_entry_points=[
            "public_delete_user_view",
            "/api/v1/public/delete_user",
            "public_app.route",
            "document_view",
            "/api/v1/documents",
        ],
        required_root_cause_concepts=[
            ["bypass", "divergence", "unprotected", "public", "missing auth", "unauthenticated", "idor", "tenant"],
            ["delete_user", "document", "admin_required", "ownership", "scope"],
        ],
        disqualifying_misattributions=[
            "command injection",
            "rce",
            "prototype pollution",
            "insecure deserialization",
            "xss",
        ],
        supported_impact=(
            "Administrative authorization bypass: Sensitive user deletion service is protected by "
            "@admin_required in admin_controller.py but exposed without authorization in public_controller.py, "
            "allowing unauthenticated attackers to delete user accounts."
        ),
        overstated_impact_patterns=[
            "remote code execution",
            "arbitrary host command execution",
        ],
        safe_mitigation_checks=[
            "@admin_required on public_delete_user_view",
            "tenant_id filter on fetch_document",
        ],
    ),
}

