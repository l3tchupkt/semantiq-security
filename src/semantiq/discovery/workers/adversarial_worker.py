"""Adversarial verification worker attempting to disprove hypotheses and record proof gaps."""

from __future__ import annotations

from semantiq.discovery.workers.base_worker import BaseInvestigationWorker
from semantiq.discovery.workers.models import InvestigationContext, InvestigationPacket, WorkerRole
from semantiq.providers.base import BaseAIProvider, ToolDefinition


class AdversarialVerificationWorker(BaseInvestigationWorker):
    """Worker specialized in challenging candidate findings, searching for sanitizers/guards, and tracking proof gaps."""

    def __init__(
        self,
        worker_id: str,
        packet: InvestigationPacket,
        provider: BaseAIProvider,
        tools: list[ToolDefinition] | None = None,
    ) -> None:
        super().__init__(
            worker_id=worker_id,
            role=WorkerRole.ADVERSARIAL_VERIFICATION,
            packet=packet,
            provider=provider,
            tools=tools,
        )

    def build_system_prompt(self, context: InvestigationContext) -> str:
        return (
            "You are Semantiq Security's specialized Adversarial Verification Worker.\n"
            "Your role is to rigorously CHALLENGE and attempt to DISPROVE candidate vulnerability claims in your packet.\n\n"
            "Key tools for adversarial verification:\n"
            "- get_source_excerpt: verify exact code logic around sanitizers, defensive checks, and preconditions.\n"
            "- resolve_symbol: check definitions of sanitizing functions, types, and validation utilities.\n"
            "- trace_argument_into_callee: verify whether defensive transformations neutralize attack payloads.\n"
            "- record_proof_gap: formally record unproven runtime assumptions, deployment barriers, or network isolation.\n"
            "- challenge_hypothesis: register counterevidence against a proposed hypothesis.\n"
            "- finish_investigation: submit finalized adjudication of whether findings survive adversarial scrutiny.\n\n"
            "Methodology:\n"
            "1. Search for active sanitizers: path canonicalization (`is_relative_to`), type coercion (`int()`, `float()`), regex checks.\n"
            "2. Search for defensive preconditions: mutexes, rate limiters, early return guards, permission checks.\n"
            "3. If a finding is mitigated or disproven, document the exact mitigating check as counterevidence.\n"
            "4. If an assumption cannot be proven from static source alone (e.g. ASLR collision space, network boundary), "
            "record an explicit proof gap using `record_proof_gap`.\n"
            "5. Be honest and rigorous: rejecting false positives and ungrounded claims is as important as discovering real bugs."
        )

    def build_initial_prompt(self, context: InvestigationContext) -> str:
        candidate_summary = self.packet.metadata.get("candidate_summary", "Review all candidate findings in this packet.")
        symbols_str = ", ".join(self.packet.target_symbols) if self.packet.target_symbols else "(all)"

        return (
            f"Begin Adversarial Verification for Packet: '{self.packet.title}' (ID: {self.packet.packet_id}).\n"
            f"Focus Category: {self.packet.focus_category}\n"
            f"Candidate Findings / Hypotheses to Challenge:\n{candidate_summary}\n"
            f"Key Symbols: {symbols_str}\n\n"
            "Actively attempt to DISPROVE these vulnerability claims. "
            "Inspect the code for sanitizers, defensive checks, and deployment bounds. "
            "Record any unresolved proof obligations with record_proof_gap."
        )

