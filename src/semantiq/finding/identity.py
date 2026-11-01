"""Root-cause-aware semantic finding identity model.

Identifies security failures by underlying architectural defect, violated security invariant,
entrypoint and dataflow sink, rather than shallow file path, line number, or rule ID.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from semantiq.models import CodeEvidenceRole, Finding, VulnerabilityCategory


class SecurityInvariant(str, Enum):
    """Core security invariants expected to hold across the software system."""

    AUTH_ENFORCEMENT = "auth_enforcement"
    AUTHORIZATION_CHECK = "authorization_check"
    PATH_CONTAINMENT = "path_containment"
    INPUT_NEUTRALIZATION = "input_neutralization"
    SESSION_INTEGRITY = "session_integrity"
    ORIGIN_INTEGRITY = "origin_integrity"
    DYNAMIC_DISPATCH_BOUND = "dynamic_dispatch_bound"
    DATA_PRIVACY = "data_privacy"
    SYSTEM_INTEGRITY = "system_integrity"


class AttackerCapability(str, Enum):
    """Attacker capabilities or access levels required to exploit a defect."""

    NETWORK_UNAUTHENTICATED = "network_unauthenticated"
    NETWORK_AUTHENTICATED = "network_authenticated"
    BROWSER_CROSS_ORIGIN = "browser_cross_origin"
    INTERNAL_NETWORK = "internal_network"
    LOCAL_UNPRIVILEGED = "local_unprivileged"
    LOCAL_PHYSICAL = "local_physical"


class RootCauseFamily(str, Enum):
    """Classification of the underlying root cause of a vulnerability."""

    MISSING_AUTHENTICATION = "missing_authentication"
    MISSING_AUTHORIZATION = "missing_authorization"
    PATH_TRAVERSAL_UNSANITIZED = "path_traversal_unsanitized"
    COMMAND_INJECTION_UNESCAPED = "command_injection_unescaped"
    WEAK_PRNG_SESSION = "weak_prng_session"
    CSRF_MISSING_TOKEN = "csrf_missing_token"
    DYNAMIC_ATTRIBUTE_INJECTION = "dynamic_attribute_injection"
    INSECURE_DIRECT_OBJECT_REFERENCE = "insecure_direct_object_reference"
    SQL_INJECTION_UNPARAMETERIZED = "sql_injection_unparameterized"
    GENERIC_LOGIC_FLAW = "generic_logic_flaw"


class SemanticFindingIdentity(BaseModel):
    """Semantic identity of a finding based on invariant, root cause, and causal dataflow."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    root_cause_family: RootCauseFamily
    security_invariant: SecurityInvariant
    subsystem_or_module: str = Field(default="")
    entry_point: str = Field(default="")
    target_sink: str = Field(default="")
    required_capability: AttackerCapability = Field(default=AttackerCapability.NETWORK_UNAUTHENTICATED)
    exploit_prerequisites: list[str] = Field(default_factory=list)
    relevant_mitigations: list[str] = Field(default_factory=list)
    structural_hash: str = Field(default="")
    semantic_fingerprint: str = Field(default="")

    def __init__(self, **data: Any) -> None:
        if "sensitive_sink" in data and "target_sink" not in data:
            data["target_sink"] = data.pop("sensitive_sink")
        super().__init__(**data)
        if not self.structural_hash or not self.semantic_fingerprint:
            s_hash, sem_fp = self._compute_hashes()
            object.__setattr__(self, "structural_hash", s_hash)
            object.__setattr__(self, "semantic_fingerprint", sem_fp)

    @property
    def sensitive_sink(self) -> str:
        """Alias for target_sink."""
        return self.target_sink

    def _compute_hashes(self) -> tuple[str, str]:
        """Compute deterministic structural and semantic hashes."""
        # Structural hash identifies the invariant failure and attacker capability
        struct_data = {
            "root_cause_family": self.root_cause_family.value,
            "security_invariant": self.security_invariant.value,
            "required_capability": self.required_capability.value,
        }
        struct_raw = json.dumps(struct_data, sort_keys=True)
        struct_hash = hashlib.sha256(struct_raw.encode("utf-8")).hexdigest()[:16]

        # Semantic fingerprint includes subsystem, normalized entry point, and sink
        norm_entry = self.entry_point.lower().replace("//", "/").strip()
        norm_sink = self.target_sink.lower().strip()
        sem_data = {
            "structural_hash": struct_hash,
            "subsystem": self.subsystem_or_module.lower().strip(),
            "entry_point": norm_entry,
            "target_sink": norm_sink,
        }
        sem_raw = json.dumps(sem_data, sort_keys=True)
        sem_fp = hashlib.sha256(sem_raw.encode("utf-8")).hexdigest()[:24]

        return struct_hash, sem_fp

    def matches_root_cause(self, other: SemanticFindingIdentity) -> bool:
        """Return True if both identities share the exact same root cause, invariant, and sink compatibility."""
        if self.root_cause_family != other.root_cause_family or self.security_invariant != other.security_invariant:
            return False
        # Sinks must match if both are specified and non-empty
        if self.target_sink and other.target_sink:
            return self.target_sink.lower().strip() == other.target_sink.lower().strip()
        # If neither has a concrete sink, they match only within the same subsystem/module
        if not self.target_sink and not other.target_sink:
            return self.subsystem_or_module.lower().strip() == other.subsystem_or_module.lower().strip()
        return False

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        graph: Any | None = None,
    ) -> SemanticFindingIdentity:
        """Derive semantic identity from a finding model and optional semantic graph context."""
        if finding.metadata and "semantic_identity" in finding.metadata:
            meta_id = finding.metadata["semantic_identity"]
            if isinstance(meta_id, SemanticFindingIdentity):
                return meta_id
            if isinstance(meta_id, dict):
                try:
                    return SemanticFindingIdentity.model_validate(meta_id)
                except Exception:
                    pass

        title_lower = (finding.title or "").lower()
        summary_lower = (finding.summary or "").lower()
        file_lower = (finding.file_path or "").lower()
        combined_text = f"{title_lower} {summary_lower} {finding.rule_id.lower()}"

        # 1. Deduce root cause family & security invariant
        # Prioritize explicit finding.category over loose keyword substrings in title/rule_id
        if finding.category in (VulnerabilityCategory.AUTHORIZATION_BYPASS, VulnerabilityCategory.AUTHENTICATION_BYPASS):
            root_cause = RootCauseFamily.MISSING_AUTHORIZATION
            invariant = SecurityInvariant.AUTHORIZATION_CHECK
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED
        elif finding.category == VulnerabilityCategory.PATH_TRAVERSAL:
            root_cause = RootCauseFamily.PATH_TRAVERSAL_UNSANITIZED
            invariant = SecurityInvariant.PATH_CONTAINMENT
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED
        elif finding.category == VulnerabilityCategory.COMMAND_INJECTION:
            root_cause = RootCauseFamily.COMMAND_INJECTION_UNESCAPED
            invariant = SecurityInvariant.INPUT_NEUTRALIZATION
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED
        elif finding.category == VulnerabilityCategory.INSECURE_CRYPTO:
            root_cause = RootCauseFamily.WEAK_PRNG_SESSION
            invariant = SecurityInvariant.SESSION_INTEGRITY
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED
        elif "traversal" in combined_text or "relative_to" in combined_text:
            root_cause = RootCauseFamily.PATH_TRAVERSAL_UNSANITIZED
            invariant = SecurityInvariant.PATH_CONTAINMENT
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED
        elif "command" in combined_text or "exec" in combined_text:
            root_cause = RootCauseFamily.COMMAND_INJECTION_UNESCAPED
            invariant = SecurityInvariant.INPUT_NEUTRALIZATION
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED
        elif "csrf" in combined_text or "origin" in combined_text or "referer" in combined_text or "_enforce_same_origin" in combined_text:
            root_cause = RootCauseFamily.CSRF_MISSING_TOKEN
            invariant = SecurityInvariant.ORIGIN_INTEGRITY
            capability = AttackerCapability.BROWSER_CROSS_ORIGIN
        elif "setattr" in combined_text or "getattr" in combined_text or "dynamic_dispatch" in combined_text:
            root_cause = RootCauseFamily.DYNAMIC_ATTRIBUTE_INJECTION
            invariant = SecurityInvariant.DYNAMIC_DISPATCH_BOUND
            capability = AttackerCapability.LOCAL_UNPRIVILEGED if "tests" in file_lower or "test" in file_lower else AttackerCapability.NETWORK_UNAUTHENTICATED
        elif "auth" in combined_text or "login" in combined_text:
            root_cause = RootCauseFamily.MISSING_AUTHENTICATION
            invariant = SecurityInvariant.AUTH_ENFORCEMENT
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED
        else:
            root_cause = RootCauseFamily.GENERIC_LOGIC_FLAW
            invariant = SecurityInvariant.SYSTEM_INTEGRITY
            capability = AttackerCapability.NETWORK_UNAUTHENTICATED

        # 2. Extract Entry Point
        entry_point = ""
        if finding.locations:
            for loc in finding.locations:
                if loc.role == "entry_point" and loc.symbol:
                    entry_point = loc.symbol
                    break
        if not entry_point:
            # Check code evidence for entrypoint or user input
            for ev in finding.code_evidence:
                if ev.role in (CodeEvidenceRole.ENTRYPOINT, CodeEvidenceRole.USER_INPUT) and ev.snippet:
                    entry_point = ev.snippet.split("\n")[0][:60]
                    break
        if not entry_point:
            # Parse route tokens like /admin/delete_user, /cmd, etc.
            import re
            route_match = re.search(r"(/[a-zA-Z0-9_/-]+)", combined_text)
            if route_match:
                entry_point = route_match.group(1).strip()
        # If no specific entry point symbol or route is identified, keep entry_point empty.
        # Do not default to file_path, which falsely equates all distinct endpoints in the same file.

        # 3. Extract Target Sink from verified evidence or locations
        target_sink = ""
        for ev in finding.code_evidence:
            if ev.role == CodeEvidenceRole.SINK and ev.snippet:
                target_sink = ev.snippet.split("\n")[0][:60].strip()
                break
        if not target_sink and finding.locations:
            for loc in finding.locations:
                if loc.role == "sink" and loc.symbol:
                    target_sink = loc.symbol.strip()
                    break
        # Do not synthesize speculative or fake sinks when evidence is missing.
        # An empty target_sink honestly indicates an unverified sink.

        # 4. Extract Subsystem / Module
        parts = finding.file_path.replace("\\", "/").split("/")
        subsystem = "/".join(parts[:-1]) if len(parts) > 1 else parts[0]

        # 5. Extract Prerequisites & Mitigations
        prereqs = list(finding.prerequisites or [])
        mitigations = list(finding.sanitizers_considered or [])
        if "is_relative_to" in combined_text:
            mitigations.append("pathlib.is_relative_to")
        if "_enforce_same_origin" in combined_text:
            mitigations.append("_enforce_same_origin")

        return cls(
            root_cause_family=root_cause,
            security_invariant=invariant,
            subsystem_or_module=subsystem,
            entry_point=entry_point,
            target_sink=target_sink,
            required_capability=capability,
            exploit_prerequisites=prereqs,
            relevant_mitigations=mitigations,
        )
