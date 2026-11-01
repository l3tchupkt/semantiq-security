"""Discovery worker forming initial vulnerability hypotheses across entrypoints and sinks."""

from __future__ import annotations

from semantiq.discovery.workers.base_worker import BaseInvestigationWorker
from semantiq.discovery.workers.models import InvestigationContext, InvestigationPacket, WorkerRole
from semantiq.providers.base import BaseAIProvider, ToolDefinition


class DiscoveryWorker(BaseInvestigationWorker):
    """Worker specialized in exploring entrypoints, routing trees, and identifying candidate vulnerabilities."""

    def __init__(
        self,
        worker_id: str,
        packet: InvestigationPacket,
        provider: BaseAIProvider,
        tools: list[ToolDefinition] | None = None,
    ) -> None:
        super().__init__(
            worker_id=worker_id,
            role=WorkerRole.DISCOVERY,
            packet=packet,
            provider=provider,
            tools=tools,
        )

    def build_system_prompt(self, context: InvestigationContext) -> str:
        return (
            "You are Semantiq Security's specialized Discovery Worker.\n"
            "Your role is to explore web entrypoints, routing handlers, and sensitive operations in your assigned packet, "
            "form high-impact vulnerability hypotheses, and gather source code evidence.\n\n"
            "Key tools for discovery:\n"
            "- find_routes_reaching_sensitive_operation: identify routes reaching sensitive operations and examine guards.\n"
            "- resolve_symbol: inspect class definitions, methods, parameters, and decorators.\n"
            "- show_unresolved_dynamic_dispatch: check reflection or dynamic invocation sites in this subsystem.\n"
            "- get_source_excerpt: verify exact source code snippets.\n"
            "- record_hypothesis: record an explicit vulnerability hypothesis for deeper investigation.\n"
            "- finish_investigation: submit finalized candidate findings with code evidence.\n\n"
            "Methodology:\n"
            "1. Inspect the packet's target entrypoints and sinks.\n"
            "2. Determine whether user input can reach high-impact operations (command execution, file access, crypto, bypasses).\n"
            "3. Ground all evidence in exact file paths and line ranges.\n"
            "4. Never invent nonexistent files or hallucinate code."
        )

    def build_initial_prompt(self, context: InvestigationContext) -> str:
        entrypoints_str = (
            ", ".join(self.packet.entrypoint_ids)
            if self.packet.entrypoint_ids
            else "(none specified)"
        )
        sinks_str = ", ".join(self.packet.sink_ids) if self.packet.sink_ids else "(none specified)"
        symbols_str = (
            ", ".join(self.packet.target_symbols) if self.packet.target_symbols else "(all)"
        )
        files_str = (
            ", ".join(self.packet.file_paths) if self.packet.file_paths else "(all repo files)"
        )

        return (
            f"Begin Discovery investigation for Packet: '{self.packet.title}' (ID: {self.packet.packet_id}).\n"
            f"Focus Category: {self.packet.focus_category}\n"
            f"Priority: {self.packet.priority}/10\n"
            f"Description: {self.packet.description}\n"
            f"Target Entrypoints: {entrypoints_str}\n"
            f"Target Sinks: {sinks_str}\n"
            f"Key Symbols: {symbols_str}\n"
            f"Files in Scope: {files_str}\n\n"
            "Explore these entrypoints and sinks using your discovery tools. Form hypotheses and submit candidate findings."
        )
