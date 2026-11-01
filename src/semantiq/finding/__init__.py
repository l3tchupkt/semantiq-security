"""Finding intelligence, semantic identity, and evidence-preserving deduplication package."""

from semantiq.finding.deduplication import (
    DeduplicationResult,
    EquivalenceDecision,
    EquivalenceOutcome,
    MergeAuditRecord,
    SemanticDeduplicator,
)
from semantiq.finding.identity import (
    AttackerCapability,
    RootCauseFamily,
    SecurityInvariant,
    SemanticFindingIdentity,
)

__all__ = [
    "AttackerCapability",
    "DeduplicationResult",
    "EquivalenceDecision",
    "EquivalenceOutcome",
    "MergeAuditRecord",
    "RootCauseFamily",
    "SecurityInvariant",
    "SemanticDeduplicator",
    "SemanticFindingIdentity",
]

