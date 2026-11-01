# Semantiq Security — Implementation & Parity Roadmap

## Executive Summary

This roadmap establishes a phased, prioritized architectural plan to elevate **Semantiq Security** to capability parity with the core investigation, validation, and reduction strengths of **Codex Security**.

All proposed improvements strictly adhere to Semantiq's non-negotiable engineering constraints:
- **Package Version:** Locked strictly at `0.1.0`.
- **Repository Access:** Maintained as private; no public releases, no PyPI publishing, no release tags.
- **Safety Invariant:** All analysis remains offline-first and read-only by default; target repository code is never executed without explicit, isolated sandboxing.
- **Evidentiary Standard:** No fabricated metrics or claims; progress is validated through reproducible benchmarks.

---

## 1. Prioritized Roadmap Overview

```
                                  ┌────────────────────────────────────────────────────────┐
                                  │      Semantiq Security Implementation Roadmap (0.1.0)  │
                                  └───────────────────────────┬────────────────────────────┘
                                                              │
                    ┌─────────────────┬───────────────────────┼───────────────────────┬─────────────────┐
                    │                 │                       │                       │                 │
                    ▼                 ▼                       ▼                       ▼                 ▼
             ┌─────────────┐   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐   ┌─────────────┐
             │   Phase 1   │   │   Phase 2   │         │   Phase 3   │         │   Phase 4   │   │   Phase 5   │
             │   Finding   │   │   Policy    │         │  Parallel   │         │  Two-Stage  │   │ Patch Risk  │
             │  Contract   │   │  & Threat   │         │  Deep Scan  │         │ Dedupe &    │   │  & Auto-    │
             │  Hardening  │   │   Packets   │         │ Coordinator │         │ Persistence │   │ Merge Gate  │
             └─────────────┘   └─────────────┘         └─────────────┘         └─────────────┘   └─────────────┘
```

---

## 2. Phase-by-Phase Specification

### Phase 1: Finding Contract Hardening & Rich Evidence Schema
**Goal:** Upgrade Semantiq's finding data model, evidence schema, and citation verifier to match Codex's role-based evidence and proof-gap standards.

- **Milestone 1.1: Semantic CodeEvidence Roles**
  - Update `CodeEvidence` in [`src/semantiq/models.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/models.py):
    - Add enum `CodeEvidenceRole`: `user_input`, `entrypoint`, `propagation`, `root_control`, `sink`, `outcome`, `expected_control`.
    - Add field `explanation: str` to record the connective step-by-step reasoning explaining why the lines preserve or violate an invariant.
  - Update `Finding` in `src/semantiq/models.py`:
    - Add `root_cause_evidence_refs: list[str]` (ordered list of evidence IDs).
    - Add `proof_gaps: list[str]` to record unproven runtime or deployment assumptions.
    - Add `counterevidence_notes: list[str]`.
- **Milestone 1.2: Scan Contract Sealing & Finalization**
  - Implement `src/semantiq/reporting/contract_finalizer.py`:
    - Enforce non-empty code snippets, exact disk line verification, and JSON schema conformity.
    - Seal scan directories with read-only permissions and SHA-256 manifests.
  - Update SARIF exporter ([`src/semantiq/reporting/exporter.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/reporting/exporter.py)) to map severities to numerical security scores (9.5 Critical, 8.0 High, 5.0 Medium, 2.0 Low) conforming to GitHub/NIST SARIF standards.
- **Acceptance Criteria & Verification:**
  - Unit tests in `tests/unit/test_finding_contract_hardening.py` verifying all 7 evidence roles, proof-gap recording, and sealed manifest generation.
  - `ruff check .` and `mypy src/semantiq` pass with 0 errors.

---

### Phase 2: Policy Grounding & Investigation Packet Partitioning
**Goal:** Ground Semantiq investigations in repository `SECURITY.md` guidance and partition large codebases into focused investigation packets.

- **Milestone 2.1: Security Policy Grounding (`SECURITY.md`)**
  - Implement `src/semantiq/repository/policy.py` (`SecurityPolicyResolver`):
    - Discovers and parses root and component-scoped `SECURITY.md` files.
    - Extracts supported surfaces, deployment modes, attacker roles, and explicit exclusions.
  - Integrate `SecurityPolicyResolver` into `ThreatModelExtractor` ([`src/semantiq/threat_model/generator.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/threat_model/generator.py)).
- **Milestone 2.2: Investigation Packet Partitioner**
  - Implement `src/semantiq/discovery/partitioner.py` (`InvestigationPacketPartitioner`):
    - Uses SPG route clusters and file directory boundaries to group target files into self-contained investigation packets.
    - Formulates packet hypotheses: `(Attacker Role, Entrypoint, Expected Invariant, Target Sinks, Scope Files)`.
- **Acceptance Criteria & Verification:**
  - Unit tests in `tests/unit/test_policy_and_packet_partitioning.py` verifying policy resolution and packet clustering across multi-component apps.
  - Benchmark on NASA-AMMOS AIT-GUI confirming that `SECURITY.md` guidelines are respected during threat modeling.

---

### Phase 3: Parallel Deep Scan Orchestration (Workers & Reducer)
**Goal:** Implement a multi-worker coordination engine that overcomes the single-thread turn-budget limitation on large repositories.

- **Milestone 3.1: Deep Scan Coordinator (`InvestigationCoordinator`)**
  - Implement `src/semantiq/discovery/coordinator.py`:
    - Manages worker pool lifecycle, turn budgets per worker, and incremental candidate checkpointing (`record_scan_draft`).
    - Spawns independent discovery workers (`fork_turns: "none"`) using Semantiq subagents or worker threads.
- **Milestone 3.2: Investigation Reducer (`InvestigationReducer`)**
  - Implement `src/semantiq/discovery/reducer.py`:
    - Collects candidate findings emitted by parallel workers.
    - Merges overlapping candidates across sub-scopes.
    - Resolves cross-component attack chains spanning worker boundaries.
- **Acceptance Criteria & Verification:**
  - Integration test in `tests/integration/test_parallel_deep_scan.py` running 3 parallel discovery workers on a multi-service fixture.
  - Benchmark measuring wall-clock duration and coverage on 500+ file repository.

---

### Phase 4: Two-Stage Finding Deduplication & Full Workbench Storage
**Goal:** Replace exact fingerprint hashing with semantic neighborhood deduplication, and expand SQLite persistence to track complete scan history.

- **Milestone 4.1: Two-Stage Deduplication Engine**
  - Implement `src/semantiq/discovery/deduplication.py`:
    - Stage 1 (Screening): Clusters candidate findings by file path, component, and root-cause similarity.
    - Stage 2 (Pairwise Review): Prompts an LLM reviewer to evaluate candidate pairs (`SAME` vs `DISTINCT`) and synthesize an inclusive `mergedFinding`.
- **Milestone 4.2: Workbench SQLite Schema Expansion**
  - Update [`src/semantiq/storage/sqlite.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/storage/sqlite.py):
    - Add tables: `scans`, `scan_progress`, `finding_occurrences`, `finding_dedupe_groups`, `coverage_surfaces`, `triage_records`.
    - Implement migration history tracker (`schema_migrations`).
- **Acceptance Criteria & Verification:**
  - Unit tests in `tests/unit/test_two_stage_deduplication.py` confirming that 10 candidate duplicates collapse into correct canonical findings without dropping locations.
  - Storage persistence tests verifying multi-scan history retention.

---

### Phase 5: Patch Risk Assessment & Automated Regression Verification
**Goal:** Elevate patch proposals into comprehensive patch risk assessments with regression tests and auto-merge rubrics.

- **Milestone 5.1: Patch Risk Evaluator**
  - Implement `src/semantiq/remediation/risk_evaluator.py`:
    - Analyzes AST diffs to identify semantic changes, affected callers, and boundary mutations.
    - Evaluates safety falsification and regression protections.
    - Emits recommendations: `merge (auto_merge_candidate | human_review_required)`, `revise`, `no_op`, `block`.
- **Milestone 5.2: Verification Engine Integration**
  - Update [`src/semantiq/remediation/verifier.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/remediation/verifier.py) to execute generated regression test specifications in isolated in-memory AST copies.
- **Acceptance Criteria & Verification:**
  - Unit tests in `tests/unit/test_patch_risk_assessment.py` evaluating benign vs breaking patches.

---

## 3. Engineering Quality Gates for All Phases

Every milestone delivery must strictly fulfill the standard Semantiq quality gates:
1. Version locked at `0.1.0` in `pyproject.toml` and public APIs.
2. `python -m ruff check src/semantiq tests/` returns 0 errors.
3. `python -m mypy src/semantiq` returns 0 type errors across all files.
4. `python -m pytest` passes with 100% success rate across all test suites.
5. All target repositories (`NASA-AMMOS/AIT-GUI`, `AIT-Core`) remain completely clean and unmodified.

