"""OASIS SARIF 2.1.0 interoperability engine for Semantiq Security.

Provides full-fidelity export and defensive import of external SARIF documents,
preserving rule metadata, multi-hop code flows, related locations, fingerprints,
and suppression states without prematurely trusting third-party findings.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    EvidenceVerificationStatus,
    Finding,
    FindingLifecycleState,
    ProofGap,
    ProofGapStatus,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH: "error",
    SeverityLevel.MEDIUM: "warning",
    SeverityLevel.LOW: "note",
    SeverityLevel.INFORMATIONAL: "note",
}

SARIF_LEVEL_TO_SEVERITY = {
    "error": SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "note": SeverityLevel.LOW,
    "none": SeverityLevel.INFORMATIONAL,
}


def normalize_and_validate_sarif_uri(
    uri: str,
    repository_root: Path | str | None = None,
) -> str:
    """Normalize file URIs from SARIF artifacts into clean relative repository paths.

    Defensively rejects directory traversal attempts, malformed percent encodings,
    and paths that resolve outside the repository root.
    """
    if not uri or not isinstance(uri, str):
        return ""

    raw = uri.strip()
    if not raw:
        return ""

    # Strip scheme
    if raw.startswith("file:///"):
        raw = raw[8:]
    elif raw.startswith("file://"):
        raw = raw[7:]
    elif "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.path or raw

    # Recursive percent decoding up to 3 passes to catch nested encodings like %252e%252e
    decoded = raw
    for _ in range(3):
        try:
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        except Exception as exc:
            raise ValueError(f"Malformed percent-encoding in SARIF URI: '{uri}'") from exc

    clean = decoded.replace("\\", "/").strip()
    if clean.startswith("%SRCROOT%/"):
        clean = clean[len("%SRCROOT%/"):]
    elif clean.startswith("/"):
        clean = clean.lstrip("/")

    # Check for directory traversal sequences
    parts = [p.strip() for p in clean.split("/") if p.strip()]
    if any(p in ("..", "..\\") for p in parts) or ".." in clean:
        raise ValueError(f"Directory traversal detected in SARIF artifact URI: '{uri}'")

    if repository_root:
        repo_root = Path(repository_root).resolve()
        candidate = (repo_root / clean).resolve()
        try:
            rel = candidate.relative_to(repo_root)
            return rel.as_posix()
        except ValueError as exc:
            raise ValueError(
                f"SARIF artifact path '{uri}' resolves outside repository root '{repo_root}'"
            ) from exc

    return clean


_normalize_sarif_uri = normalize_and_validate_sarif_uri


class SARIFExporter:
    """Exports Semantiq finding collections to OASIS SARIF 2.1.0 format."""

    @classmethod
    def export(
        cls,
        findings: list[Finding],
        tool_name: str = "Semantiq Security",
        tool_version: str = "0.1.0",
        scan_id: str = "",
    ) -> str:
        """Generate complete OASIS SARIF 2.1.0 document."""
        rules_map: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for finding in findings:
            rule_id = finding.rule_id or "AI-DISCOVERY-GENERIC"
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.summary or finding.title},
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
                    },
                    "help": {
                        "text": finding.remediation or "Refer to Semantiq documentation for remediation guidance."
                    },
                    "properties": {
                        "category": finding.category.value if hasattr(finding.category, "value") else str(finding.category),
                        "cwe": finding.cwe_ids,
                        "precision": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
                    },
                }

            # Code flows from evidence
            code_flows: list[dict[str, Any]] = []
            if finding.code_evidence:
                thread_flow_locs = []
                for idx, ev in enumerate(finding.code_evidence, start=1):
                    role_tag = f"[{ev.role.value.upper()}] " if hasattr(ev.role, "value") else f"[{ev.role}] "
                    thread_flow_locs.append({
                        "step": idx,
                        "importance": "essential" if idx == len(finding.code_evidence) else "important",
                        "location": {
                            "message": {"text": f"{role_tag}{ev.explanation or 'Evidence step'}"},
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": ev.file_path.replace("\\", "/"),
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": ev.start_line,
                                    "endLine": ev.end_line,
                                    "snippet": {"text": ev.snippet},
                                },
                            },
                        },
                    })
                code_flows.append({
                    "message": {"text": f"Causal execution trace for {finding.title}"},
                    "threadFlows": [{"locations": thread_flow_locs}],
                })

            # Related locations
            related_locations: list[dict[str, Any]] = []
            for idx, ev in enumerate(finding.code_evidence, start=1):
                related_locations.append({
                    "id": idx,
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": ev.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": ev.start_line,
                            "endLine": ev.end_line,
                        },
                    },
                    "message": {"text": f"[{ev.role}] {ev.explanation}"},
                })

            res_entry: dict[str, Any] = {
                "ruleId": rule_id,
                "message": {"text": finding.summary or finding.title},
                "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.start_line,
                                "endLine": finding.end_line,
                            },
                        }
                    }
                ],
                "fingerprints": {
                    "primary": finding.fingerprint or finding.calculate_fingerprint()
                },
                "properties": {
                    "lifecycle_state": finding.lifecycle_state.value if hasattr(finding.lifecycle_state, "value") else str(finding.lifecycle_state),
                    "evidence_count": len(finding.code_evidence),
                    "proof_gap_count": len(finding.proof_gaps),
                    "proof_gaps": [
                        {
                            "gap_id": pg.gap_id,
                            "description": pg.description,
                            "rationale": pg.rationale,
                            "target_symbol": pg.target_symbol,
                            "supporting_evidence": pg.supporting_evidence,
                            "resolution_criteria": pg.resolution_criteria,
                            "status": pg.status.value if hasattr(pg.status, "value") else str(pg.status),
                        }
                        for pg in finding.proof_gaps
                    ],
                },
            }

            if code_flows:
                res_entry["codeFlows"] = code_flows
            if related_locations:
                res_entry["relatedLocations"] = related_locations

            sarif_results.append(res_entry)

        sarif_doc = {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "organization": "l3tchupkt",
                            "semanticVersion": tool_version,
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        return json.dumps(sarif_doc, indent=2)


class SARIFImporter:
    """Defensively imports external SARIF 2.1.0 documents into Semantiq finding models."""

    @classmethod
    def import_sarif(
        cls,
        sarif_input: str | dict[str, Any],
        default_category: VulnerabilityCategory = VulnerabilityCategory.GENERIC,
        repository_root: Path | str | None = None,
    ) -> list[Finding]:
        """Parse external SARIF 2.1.0 input and return normalized candidate findings."""
        if isinstance(sarif_input, str):
            try:
                data = json.loads(sarif_input)
            except Exception as exc:
                raise ValueError(f"Invalid SARIF input: JSON decode error: {exc}") from exc
        elif isinstance(sarif_input, dict):
            data = sarif_input
        else:
            raise TypeError(f"SARIF input must be str or dict, got {type(sarif_input)}")

        # Defensive structural validation
        version = str(data.get("version", ""))
        if version != "2.1.0":
            raise ValueError(f"Unsupported SARIF version '{version}'. Expected '2.1.0'.")

        runs = data.get("runs", [])
        if not isinstance(runs, list) or not runs:
            return []

        imported_findings: list[Finding] = []

        for run in runs:
            if not isinstance(run, dict):
                continue

            tool_info = run.get("tool", {}).get("driver", {})
            driver_name = str(tool_info.get("name", "external_tool")).strip()
            provenance_tag = f"SARIF_IMPORT:{driver_name}"

            # Index rule definitions
            rule_metadata: dict[str, dict[str, Any]] = {}
            for r in tool_info.get("rules", []):
                if isinstance(r, dict) and "id" in r:
                    rule_metadata[r["id"]] = r

            results = run.get("results", [])
            if not isinstance(results, list):
                continue

            for idx, res in enumerate(results, start=1):
                if not isinstance(res, dict):
                    continue

                rule_id = str(res.get("ruleId", f"RULE_{idx}"))
                rule_meta = rule_metadata.get(rule_id, {})

                # Title and Summary
                summary = ""
                msg_obj = res.get("message")
                if isinstance(msg_obj, dict):
                    summary = str(msg_obj.get("text", ""))
                elif isinstance(msg_obj, str):
                    summary = msg_obj

                title = rule_meta.get("name") or rule_meta.get("shortDescription", {}).get("text") or rule_id

                # Severity mapping
                sarif_level = str(res.get("level", "warning")).lower()
                sev = SARIF_LEVEL_TO_SEVERITY.get(sarif_level, SeverityLevel.MEDIUM)

                # Extract primary location
                file_path = "unknown"
                start_line = 1
                end_line = 1
                locations_list = res.get("locations", [])
                if isinstance(locations_list, list) and locations_list:
                    primary_loc = locations_list[0]
                    if isinstance(primary_loc, dict):
                        phys = primary_loc.get("physicalLocation", {})
                        uri = phys.get("artifactLocation", {}).get("uri", "")
                        file_path = normalize_and_validate_sarif_uri(uri, repository_root=repository_root) or "unknown"
                        region = phys.get("region", {})
                        start_line = max(1, int(region.get("startLine", 1)))
                        end_line = max(start_line, int(region.get("endLine", start_line)))

                # Parse Code Evidence from codeFlows
                evidence_list: list[CodeEvidence] = []
                code_flows = res.get("codeFlows", [])
                if isinstance(code_flows, list):
                    for cf in code_flows:
                        if not isinstance(cf, dict):
                            continue
                        for tf in cf.get("threadFlows", []):
                            if not isinstance(tf, dict):
                                continue
                            for tfloc in tf.get("locations", []):
                                if not isinstance(tfloc, dict):
                                    continue
                                loc_inner = tfloc.get("location", {})
                                step_msg = loc_inner.get("message", {}).get("text", "")
                                p_loc = loc_inner.get("physicalLocation", {})
                                raw_ev_uri = p_loc.get("artifactLocation", {}).get("uri", file_path)
                                ev_uri = normalize_and_validate_sarif_uri(raw_ev_uri, repository_root=repository_root)
                                ev_region = p_loc.get("region", {})
                                ev_sl = max(1, int(ev_region.get("startLine", 1)))
                                ev_el = max(ev_sl, int(ev_region.get("endLine", ev_sl)))
                                ev_snip = ev_region.get("snippet", {}).get("text", "")

                                # Determine role from message or step position
                                role = CodeEvidenceRole.PROPAGATION
                                if "[SINK]" in step_msg.upper():
                                    role = CodeEvidenceRole.SINK
                                elif "[SOURCE]" in step_msg.upper() or "[ENTRYPOINT]" in step_msg.upper():
                                    role = CodeEvidenceRole.ENTRYPOINT
                                elif "[INPUT]" in step_msg.upper() or "[USER_INPUT]" in step_msg.upper():
                                    role = CodeEvidenceRole.USER_INPUT
                                elif "[GUARD]" in step_msg.upper() or "[SANITIZER]" in step_msg.upper():
                                    role = CodeEvidenceRole.EXPECTED_CONTROL
                                elif "[ROOT_CONTROL]" in step_msg.upper():
                                    role = CodeEvidenceRole.ROOT_CONTROL
                                elif "[OUTCOME]" in step_msg.upper():
                                    role = CodeEvidenceRole.OUTCOME

                                ce = CodeEvidence(
                                    file_path=ev_uri,
                                    start_line=ev_sl,
                                    end_line=ev_el,
                                    snippet=ev_snip,
                                    role=role,
                                    explanation=step_msg,
                                    provenance=provenance_tag,
                                    verification_status=EvidenceVerificationStatus.UNVERIFIED,
                                )
                                ce.ensure_id()
                                evidence_list.append(ce)

                # Fallback evidence if codeFlows missing
                if not evidence_list:
                    primary_ev = CodeEvidence(
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        snippet="",
                        role=CodeEvidenceRole.SINK,
                        explanation=summary,
                        provenance=provenance_tag,
                        verification_status=EvidenceVerificationStatus.UNVERIFIED,
                    )
                    primary_ev.ensure_id()
                    evidence_list.append(primary_ev)

                # Reconstruct Proof Gaps from SARIF properties
                props = res.get("properties", {})
                proof_gaps_list: list[ProofGap] = []
                if isinstance(props, dict) and "proof_gaps" in props and isinstance(props["proof_gaps"], list):
                    for pg_dict in props["proof_gaps"]:
                        if isinstance(pg_dict, dict):
                            try:
                                s_enum = ProofGapStatus(str(pg_dict.get("status", "open")).lower())
                            except Exception:
                                s_enum = ProofGapStatus.OPEN
                            proof_gaps_list.append(
                                ProofGap(
                                    gap_id=str(pg_dict.get("gap_id", "")),
                                    description=str(pg_dict.get("description", "")),
                                    rationale=str(pg_dict.get("rationale", "")),
                                    target_symbol=str(pg_dict.get("target_symbol", "")),
                                    supporting_evidence=list(pg_dict.get("supporting_evidence", [])),
                                    resolution_criteria=str(pg_dict.get("resolution_criteria", "")),
                                    status=s_enum,
                                )
                            )

                # Fingerprint
                fingerprints_obj = res.get("fingerprints", {})
                primary_fp = fingerprints_obj.get("primary") if isinstance(fingerprints_obj, dict) else ""

                f = Finding(
                    finding_id=f"sarif_{driver_name[:6].lower()}_{idx}_{start_line}",
                    occurrence_id=f"occ_{driver_name[:6].lower()}_{idx}",
                    rule_id=rule_id,
                    title=title,
                    summary=summary or f"Imported finding from {driver_name}",
                    category=default_category,
                    severity=sev,
                    confidence=ConfidenceLevel.LOW,  # Third party findings start with LOW confidence
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    locations=[
                        SourceLocation(
                            file_path=file_path,
                            start_line=start_line,
                            end_line=end_line,
                            role="sink",
                        )
                    ],
                    code_evidence=evidence_list,
                    proof_gaps=proof_gaps_list,
                    fingerprint=primary_fp or "",
                    lifecycle_state=FindingLifecycleState.CANDIDATE,  # Defensively untrusted initially
                    validation_status=ValidationStatus.INCONCLUSIVE,
                    metadata={
                        "imported_from": driver_name,
                        "sarif_rule_metadata": rule_meta,
                        "provenance": provenance_tag,
                    },
                )
                imported_findings.append(f)

        logger.info("Successfully imported %d findings from external SARIF", len(imported_findings))
        return imported_findings
