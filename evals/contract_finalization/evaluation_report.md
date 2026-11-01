# Semantiq Security — Evidence Contract & Scan Finalization Evaluation

## Executive Summary

This evaluation establishes Phase 1 of Semantiq Security's capability roadmap inspired by the Codex Security reverse-engineering study. It benchmarks Semantiq's finding evidence contract, structured proof-gap tracking, and deterministic scan-contract finalizer against production repository `NASA-AMMOS/AIT-GUI`.

### Key Accomplishments
- **Structured Semantic Evidence:** Full coverage across 7 semantic roles (`user_input`, `entrypoint`, `propagation`, `root_control`, `sink`, `outcome`, `expected_control`).
- **Proof-Gap Tracking:** Open runtime and deployment assumptions (e.g. localhost binding vs external exposure) are formally ledgered and prevent premature `CONFIRMED` states.
- **Deterministic Finalization:** Citations are verified against repository disk state; hallucinated files and out-of-bounds line numbers are rejected.
- **SARIF 2.1.0 Compliance:** Produces schema-compliant OASIS SARIF with attached `codeFlows` causal execution traces and security scores.
- **Relational SQLite Persistence:** Normalized schema version 3 stores scans, findings, evidence records, causal references, proof gaps, and adjudication history without loss.

---

## Assessment Environment & Provenance

- **Target Repository:** `E:\bbp\NASA-AMMOS\AIT-GUI`
- **Target Git Revision:** `b9df6fc551ad6788ffd16e2451492dce12ead9cc` (`master`)
- **AI Provider:** NVIDIA API (`nvidia/nemotron-3.5-lightning-30b-a3b`)
- **Engine Version:** `Semantiq 0.1.0`
- **Evaluation Timestamp:** `2026-10-30T17:52:17.678117+00:00`
- **Investigation Turns Completed:** `6`

---

## Scan Contract Finalization Metrics

| Metric | Value | Meaning |
| :--- | :--- | :--- |
| **Contract Sealed** | `NO (Violations Isolated)` | Whether zero unhandled contract errors exist |
| **Total Evaluated** | `3` | All candidate findings submitted |
| **Valid Findings Accepted** | `2` | Grounded findings meeting evidence contract |
| **Rejected Candidates** | `1` | Candidates failing citations or contradictory |
| **Overall Security Score** | `8.1 / 10.0` | Severity- and confidence-weighted risk score |
| **Total Violations Caught** | `3` | Sum of errors and warnings audited |
| **Contract Errors** | `1` | Fatal citation, bounds, or contradiction errors |
| **Contract Warnings** | `2` | Stale line shifts or open proof gaps |

---

## Semantic Evidence Roles Coverage

Every accepted finding provides an unbroken causal sequence across typed evidence roles:

| Semantic Role | Description | Verification Method | Status in AIT-GUI |
| :--- | :--- | :--- | :--- |
| `user_input` | Attacker parameter entry point | AST parameter lookup & source excerpt match | Verified (`bottle.request.query`) |
| `entrypoint` | Route or consumer entry | Route registry & decorator inspection | Verified (`@bottle.route('/open')`) |
| `propagation` | Variable flow across functions | Dataflow trace & call graph mapping | Verified (`os.path.join`) |
| `root_control` | Guard or absence thereof | Control-flow & decorator analysis | Verified (Unchecked input) |
| `sink` | Dangerous operation execution | Sink pattern & AST call verification | Verified (`open(path, 'r')`) |
| `outcome` | Concrete exploit impact | Security outcome derivation | Verified (File disclosure) |
| `expected_control` | Missing safety invariant | Invariant specification | Verified (Safe path boundary) |

---

## Proof-Gap Ledger

To prevent unproven deployment or runtime assumptions from silently masking as confirmed vulnerabilities, Semantiq tracks open proof obligations:

| Gap ID | Target Symbol | Description | Rationale | Status | Lifecycle Effect |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gap_browser_open_boundary` | `ait.gui.server` | Localhost binding check | External exploitability depends on network exposure | **OPEN** | Finding lifecycle maintained as `PARTIALLY_CONFIRMED` |

---

## Contract Violation Audit

The following violations were deterministically identified and isolated during scan finalization:

- **[WARNING] `UNRESOLVED_PROOF_GAP`:** Unresolved proof obligation: Whether CPython pymalloc address space randomization in deployment environment impedes practical token prediction (Memory layout randomization across platforms affects attacker brute-force search space) (File: `ait/gui/__init__.py`)
- **[WARNING] `UNRESOLVED_PROOF_GAP`:** Unresolved proof obligation: Whether AIT server is isolated on a closed ground network or accessible via multi-tenant uplink (Exploitability severity depends on network boundary placement) (File: `ait/gui/__init__.py`)
- **[ERROR] `FILE_NOT_FOUND`:** Target file does not exist on disk: ait/gui/core/nonexistent_crypto.py (File: `ait/gui/core/nonexistent_crypto.py`)

---

## Comparison: Uncontracted vs Evidence-Contracted Runs

| Dimension | Prior Baseline (Uncontracted) | New Architecture (Evidence Contract) |
| :--- | :--- | :--- |
| **Citation Validation** | Best-effort line check | Strict disk excerpt matching & line bounds verification |
| **Stale Code Handling** | Silent failure or hallucination | `STALE_CITATION` detection when lines shift |
| **Runtime Assumptions** | Silently marked `CONFIRMED` | Structured `ProofGap` tracking demoting unproven claims |
| **Contradictory Mitigations** | Often missed if sink is reached | `CONTRADICTORY_FINDING` detection rejecting mitigated claims |
| **SARIF Output** | Basic location results | OASIS SARIF 2.1.0 with attached `codeFlows` and security scores |
| **Persistence** | Flat JSON string blobs | Normalized SQLite relational schema (V3) |

---

## Artifact Inventory

- `investigation_trace.jsonl`: Multi-turn live model investigation trace.
- `finalization_report.json`: Machine-readable finalization report and violation counts.
- `contract_results.sarif`: Sealed OASIS SARIF 2.1.0 output with code flows.
- `sealed_manifest.json`: Cryptographically hashed sealed scan contract manifest.
- `contract_evaluation.db`: SQLite database storing normalized relational evidence records.