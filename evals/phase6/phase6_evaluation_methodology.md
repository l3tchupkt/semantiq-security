# Phase 6: Skill Architecture & Capability Parity Evaluation Methodology

**Workspace:** `e:/Semantiq-Security/semantiq-security`  
**Reference Repository:** `e:/Semantiq-Security/codex-security`  
**Package Version:** `0.1.0` (Locked)  
**Date:** 2026-11-01  
**Author:** Semantiq Security Architecture Group  

---

## 1. Objective & Scope

This document defines the formal evaluation methodology for **Phase 6: Codex-Inspired Skill Architecture & Capability Parity**.

The primary objective is to verify that Semantiq's provider-agnostic, contract-governed security skills:
1. Successfully execute across real-world, unfamiliar production repositories.
2. Dynamically sequence and orchestrate modular capabilities (`threat_modeling`, `finding_discovery`, `attack_path_analysis`, `adversarial_validation`, `patch_risk_assessment`, `fix_verification`, and `scanner_ingestion`).
3. Enforce runtime sandboxing constraints (filesystem point denials, non-execution boundaries, read-only guarantees).
4. Preserve evidence provenance, worker/skill identities, and proof gaps through semantic reduction.
5. Record transparent execution telemetry without synthetic metric inflation.

---

## 2. Evaluation Targets & Ground Truth

Evaluation uses the exact pinned target repositories and ground-truth manifests established in Phase 5:

| Target ID | Repository Name | Pinned Commit | Architecture | In-Scope Path | Ground-Truth Flaws | Negative Controls |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `nasa_ait_gui` | `NASA-AMMOS/AIT-GUI` | `b9df6fc551ad6788ffd16e2451492dce12ead9cc` | Bottle Web Telemetry | `ait/gui` | 3 (`GT-AIT-01`, `02`, `03`) | 1 (`GT-AIT-04` mitigated path traversal) |
| `pyload` | `pyload/pyload` | `1b12dc7f348db8c144e0f39215680415e90ca4d2` | Flask Download Manager | `src/pyload` | 3 (`GT-PYLOAD-01`, `02`, `03`)| 0 |
| `gitpython` | `gitpython-developers/GitPython` | `3481da9618e69063464c94447167d83bd45505a9` | Python Git Wrapper | `git` | 2 (`GT-GIT-01`, `02`) | 0 |

**Total Ground Truth:** 8 unmitigated vulnerabilities across 3 repositories, plus 1 verified negative control (`GT-AIT-04`).

---

## 3. Evaluation Workflows

The Phase 6 evaluation runner executes three specialized evaluation workflows:

### Workflow A: Autonomous Skill-Driven Deep Scan
Sequences `sq.skill.threat_modeling` $\to$ `sq.skill.finding_discovery` $\to$ `sq.skill.attack_path_analysis` $\to$ `sq.skill.adversarial_validation` via `InvestigationCoordinator.coordinate_skill_investigation`. Measures:
- Precision and Recall against ground truth.
- True positive discovery rate.
- Negative control rejection rate.
- Semantic deduplication efficiency (merging without evidence loss).

### Workflow B: Remediation & Patch Risk Verification
Executes `sq.skill.patch_risk_assessment` and `sq.skill.fix_verification` against sample security patches and target code:
- Evaluates syntax validation, contract breakage risk, and merge recommendations.
- Validates read-only fix verification against known vulnerabilities.

### Workflow C: Scanner Alert Ingestion & Adjudication
Executes `sq.skill.scanner_ingestion` on external SARIF/JSON alerts:
- Verifies normalization into valid `Finding` models.
- Chains ingested alerts into adversarial verification.

---

## 4. Telemetry & Metrics Collection

For every skill execution, the harness captures:
- `skill_id`: Unique identifier.
- `provider`: Deterministic engine or live model identifier.
- `status`: `SUCCESS`, `PARTIAL`, `TIMEOUT`, `FAILED`, or `NOT_RUN`.
- `latency_seconds`: Wall-clock execution time.
- `tool_calls_count`: Number of sandboxed operations requested.
- `token_accounting`: Input, cached input, and output tokens (or explicit 0 if provider key is absent).

Artifacts generated:
- `evals/phase6/skill_discovery_metrics.json`: Full metrics JSON.
- `evals/phase6/workbench_phase6.db`: SQLite Schema V5 database.
- `evals/phase6/phase6_findings.sarif`: OASIS SARIF 2.1.0 report.

