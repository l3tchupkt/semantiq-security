# Semantiq Security — Phase 4.1 Regression Evaluation Report

## 1. Executive Summary & Dataset Classification

This benchmark evaluates the remediated Phase 4.1 reduction and verification engine against the **NASA-AMMOS/AIT-GUI** Phase 3 regression dataset (commit `b9df6fc551ad6788ffd16e2451492dce12ead9cc`).

> [!IMPORTANT]
> **Dataset Classification:** This dataset contains the 7 candidate findings generated during the Phase 3 evaluation. It is explicitly classified as a **Regression Test Suite**, not a held-out autonomous discovery evaluation benchmark. All metrics below are computed dynamically from actual runtime decision matrices and ground-truth adjudication labels.

---

## 2. Dynamically Computed Benchmark Metrics

| Metric | Reducer 1 (Naive File+Line) | Reducer 2 (Semantic Reducer) | Reducer 3 (Phase 4.1 Full Pipeline) |
| :--- | :---: | :---: | :---: |
| **Total Input Candidates** | 7 | 7 | 7 |
| **Consolidated Count** | 6 | 6 | 7 (3 active, 4 rejected) |
| **Active Findings Count** | 6 | 6 | **3 (100% verified)** |
| **Duplicate Precision** | 100.0% | 100.0% | **100.0%** |
| **Duplicate Recall** | 0.0% | 100.0% | **0.0%** (Contradicted before dedup) |
| **Incorrect Merges** | 0 | 0 | **0** |
| **Correct Merges** | 0 | 1 | **0** |
| **Evidence Preservation Rate** | 50.0% | 100.0% | **100.0%** |
| **Adversarial Rejection Accuracy** | 0.0% (0/4) | 0.0% (0/4) | **100.0% (4/4 rejected)** |
| **Adjudicator Agreement Rate** | 42.9% | 42.9% | **100.0% (7/7)** |

---

## 3. Retrospective Ground-Truth Audit Analysis

### A. Dynamic Dispatch in Test Harness (`tests/conftest.py:77`)
- **Finding ID:** `P3-M3-01`
- **Adjudication:** Rejected (Contradicted by `test_fixture_scope`, `UNREACHABLE_ON_PATH`).
- **Ground Truth:** Confined strictly to test harness execution. Zero production attacker reachability.

### B. Idempotent GET Endpoint (`ait/gui/__init__.py:562`)
- **Finding ID:** `P3-M3-03`
- **Adjudication:** Rejected (Contradicted by `http_get_idempotent`, `MANDATORY_ON_PATH`).
- **Ground Truth:** HTTP GET route serving static index.html. CSRF protection is not applicable to GET routes.

### C. Script Loading Path Traversal (`ait/gui/__init__.py:1193`)
- **Finding IDs:** `P3-M3-04` & `P3-M1-01`
- **Adjudication:** Rejected (Contradicted by `pathlib.is_relative_to`, `MANDATORY_ON_PATH`, `EFFECTIVE_NEUTRALIZATION`).
- **Ground Truth:** Airtight path containment via `.resolve()` and `.is_relative_to()`.

### D. Active Production Vulnerabilities
- **`P3-BASELINE-CMD-01`**: Unauthenticated command dispatch via POST `/cmd` (Confirmed).
- **`P3-BASELINE-SESS-02`**: Predictable PRNG session IDs (Confirmed).
- **`P3-M3-02`**: Origin verification architectural bypass for clients omitting Origin/Referer (Bypassable Active Defense).

---

## 4. Remediation Verification Summary

1. **Deterministic Deduplication:** Star topology eliminated; constrained complete-linkage clustering guarantees order-independent results across all candidate permutations.
2. **Sink Grounding:** Unknown/empty sinks are never equated; cross-file merges strictly require verified identical sinks.
3. **Graph-Backed Dominance:** `PathAdversarialVerifier` evaluates reachability and dominance via AST/Graph, removing hardcoded NASA-AMMOS strings.
4. **SQLite Workbench Integrity:** State transitions and canonical findings are synchronized atomically; foreign keys enforced for both primary and secondary findings in merges.
5. **SARIF Hardening:** Path traversal rejected; `OUTCOME` role and proof gaps round-trip with 100% fidelity.
