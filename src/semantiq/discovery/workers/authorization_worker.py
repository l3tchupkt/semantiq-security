"""Authorization worker investigating authentication, authorization, session tokens, and CSRF boundaries."""

from __future__ import annotations

from semantiq.discovery.workers.base_worker import BaseInvestigationWorker
from semantiq.discovery.workers.models import InvestigationContext, InvestigationPacket, WorkerRole
from semantiq.providers.base import BaseAIProvider, ToolDefinition


class AuthorizationWorker(BaseInvestigationWorker):
    """Worker specialized in auditing access controls, trust boundaries, session management, and CSRF."""

    def __init__(
        self,
        worker_id: str,
        packet: InvestigationPacket,
        provider: BaseAIProvider,
        tools: list[ToolDefinition] | None = None,
    ) -> None:
        super().__init__(
            worker_id=worker_id,
            role=WorkerRole.AUTHORIZATION,
            packet=packet,
            provider=provider,
            tools=tools,
        )

    def build_system_prompt(self, context: InvestigationContext) -> str:
        return (
            "You are Semantiq Security's specialized Authorization Worker.\n"
            "Your role is to investigate access controls, trust boundaries, authentication requirements, "
            "session management, role checks, and CSRF protections in your assigned packet.\n\n"
            "Key tools for authorization analysis:\n"
            "- identify_authorization_checks: examine enforced, bypassed, and unresolved guards for an entrypoint.\n"
            "- resolve_symbol: inspect decorators, class definitions, and session-handling functions.\n"
            "- get_source_excerpt: verify exact guard implementations or session token generators.\n"
            "- record_hypothesis: record identified access control defects.\n"
            "- finish_investigation: submit finalized authorization findings.\n\n"
            "Methodology:\n"
            "1. Check if the entrypoints enforce authentication middleware or decorators.\n"
            "2. Inspect how user identity or session state is validated (e.g. `Sessions.current()`, `@authenticated`).\n"
            "3. Examine session identifier generation: does it use cryptographically secure random values (CSPRNG) "
            "or weak/predictable values (e.g. heap address `id(self)`)?\n"
            "4. Check CSRF posture on state-changing endpoints (POST/PUT/DELETE): are tokens required, or can requests be forged?\n"
            "5. Distinguish ENFORCED, BYPASSED, and UNRESOLVED controls."
        )

    def build_initial_prompt(self, context: InvestigationContext) -> str:
        entrypoints_str = (
            ", ".join(self.packet.entrypoint_ids)
            if self.packet.entrypoint_ids
            else "(none specified)"
        )
        symbols_str = (
            ", ".join(self.packet.target_symbols) if self.packet.target_symbols else "(all)"
        )

        return (
            f"Begin Authorization investigation for Packet: '{self.packet.title}' (ID: {self.packet.packet_id}).\n"
            f"Focus Category: {self.packet.focus_category}\n"
            f"Priority: {self.packet.priority}/10\n"
            f"Target Entrypoints: {entrypoints_str}\n"
            f"Target Symbols: {symbols_str}\n\n"
            "Audit access controls, session generation, and CSRF protection for these entrypoints. "
            "Determine if endpoints are unguarded, if session tokens are predictable, or if permissions can be bypassed."
        )
