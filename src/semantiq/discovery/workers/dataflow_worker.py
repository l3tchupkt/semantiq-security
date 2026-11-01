"""Dataflow worker tracing attacker-controlled values through functions, transformations, and sinks."""

from __future__ import annotations

from semantiq.discovery.workers.base_worker import BaseInvestigationWorker
from semantiq.discovery.workers.models import InvestigationContext, InvestigationPacket, WorkerRole
from semantiq.providers.base import BaseAIProvider, ToolDefinition


class DataflowWorker(BaseInvestigationWorker):
    """Worker specialized in tracing argument flows, parameter bindings, transformations, and sanitizers."""

    def __init__(
        self,
        worker_id: str,
        packet: InvestigationPacket,
        provider: BaseAIProvider,
        tools: list[ToolDefinition] | None = None,
    ) -> None:
        super().__init__(
            worker_id=worker_id,
            role=WorkerRole.DATAFLOW,
            packet=packet,
            provider=provider,
            tools=tools,
        )

    def build_system_prompt(self, context: InvestigationContext) -> str:
        return (
            "You are Semantiq Security's specialized Dataflow Worker.\n"
            "Your role is to trace attacker-controlled values from web request entrypoints through functions, "
            "method invocations, transformations, and into sensitive operations (sinks).\n\n"
            "Key tools for dataflow tracing:\n"
            "- trace_argument_into_callee: trace caller argument expressions into callee parameters and sinks.\n"
            "- trace_return_to_caller: trace return values from callees back into caller variables.\n"
            "- query_callers_callees: explore callers and callees with positional/keyword argument mappings.\n"
            "- get_interprocedural_evidence_path: obtain ordered causal execution paths between entrypoints and sinks.\n"
            "- get_source_excerpt: verify code snippets for transformations or sanitizers.\n"
            "- finish_investigation: submit findings with verified propagation hops.\n\n"
            "Methodology:\n"
            "1. Identify the caller arguments where user input originates.\n"
            "2. Follow the parameter propagation into intermediate functions.\n"
            "3. Examine whether any sanitization (e.g. whitelist, regex, escaping, path normalization) is applied.\n"
            "4. Check whether the unescaped value reaches a sensitive sink (e.g. process execution, file write, SQL query).\n"
            "5. If a sanitizer exists, note it; if absent, record the complete propagation chain."
        )

    def build_initial_prompt(self, context: InvestigationContext) -> str:
        entrypoints_str = ", ".join(self.packet.entrypoint_ids) if self.packet.entrypoint_ids else "(none specified)"
        sinks_str = ", ".join(self.packet.sink_ids) if self.packet.sink_ids else "(none specified)"
        symbols_str = ", ".join(self.packet.target_symbols) if self.packet.target_symbols else "(all)"

        return (
            f"Begin Dataflow tracing for Packet: '{self.packet.title}' (ID: {self.packet.packet_id}).\n"
            f"Focus Category: {self.packet.focus_category}\n"
            f"Priority: {self.packet.priority}/10\n"
            f"Target Entrypoints: {entrypoints_str}\n"
            f"Target Sinks: {sinks_str}\n"
            f"Key Symbols: {symbols_str}\n\n"
            "Trace argument propagation from the entrypoint into the callee functions and sinks. "
            "Identify whether user input reaches the sink with or without sanitization."
        )

