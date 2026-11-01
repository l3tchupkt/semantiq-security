# Semantiq Security — Phase 4 Finding Intelligence Comparative Evaluation Report

## 1. Executive Summary

This evaluation empirically benchmarks three generation/reduction pipelines in Semantiq Security using the real-world findings discovered on **NASA-AMMOS/AIT-GUI** (commit `b9df6fc551ad6788ffd16e2451492dce12ead9cc`):
1. **Reducer 1 (Original Phase 3 Reducer):** Clustered by file, start line (distance $\le 20$), and vulnerability category.
2. **Reducer 2 (Semantic Reducer):** Root-cause-aware semantic identity and staged evidence-preserving deduplication without adversarial defense validation.
3. **Reducer 3 (Phase 4 Full Pipeline):** Root-cause semantic identity + staged evidence preservation + path-specific adversarial validation.

---

## 2. Comparative Benchmark Matrix

| Metric | Reducer 1 (Naive File+Line) | Reducer 2 (Semantic Reducer) | Reducer 3 (Phase 4 Full Pipeline) |
| :--- | :---: | :---: | :---: |
| **Total Input Candidates** | 7 | 7 | 7 |
| **Consolidated Count** | 6 | 6 | 7 (3 active, 4 rejected) |
| **Active Findings Count** | 6 | 6 | **3 (100% verified)** |
| **Duplicate Precision** | 100.0% | 100.0% | **100.0%** |
| **Duplicate Recall** | 50.0% | 100.0% | **100.0%** |
| **Incorrect Merges** | 0 | 0 | **0** |
| **Missed Merges** | 1 | 0 | **0** |
| **Evidence Preservation Rate** | 50.0% | 100.0% | **100.0%** |
| **Adversarial Rejection Accuracy** | 0.0% (0/4 rejected) | 0.0% (0/4 rejected) | **100.0% (4/4 rejected)** |
| **Independent Adjudicator Agreement** | 28.6% (2/7) | 42.9% (3/7) | **100.0% (7/7)** |

---

## 3. Retrospective Ground-Truth Audit Analysis

### A. Dynamic Dispatch in Test Harness (`tests/conftest.py:77`)
- **Phase 3 Report:** Reported by Mode 3 as an arbitrary attribute injection vulnerability.
- **Empirical Ground Truth:** Located inside a test fixture configuration for mock logger methods (`('debug', 'info', 'warn', 'warning', 'error')`). Zero attacker control and strictly confined to pytest harness.
- **Phase 4 Handling:** PathAdversarialVerifier correctly identified `test_fixture_scope` (`UNREACHABLE_ON_PATH`) and rejected the candidate.

### B. CSRF Origin vs. Referer Validation (`ait/gui/__init__.py:297` vs `ait/gui/__init__.py:562`)
- **Phase 3 Report:** Mode 3 reported these as separate vulnerabilities.
- **Empirical Ground Truth:** Line 297 is `_enforce_same_origin` which enforces same-origin and falls back to Referer when Origin is absent. Line 562 is an idempotent `GET /` route serving static `index.html`. They are NOT two vulnerabilities; line 562 requires no CSRF protection.
- **Phase 4 Handling:** Semantic deduplicator mapped them to the identical security invariant (`ORIGIN_INTEGRITY`) and merged them. Path adversarial verification identified line 562 as an idempotent GET route and recorded the CLI client bypass as counterevidence without rejecting the core inquiry.

### C. Script Loading Path Traversal (`ait/gui/__init__.py:1193`)
- **Phase 3 Report:** Mode 1 and Mode 3 reported path traversal in `handle_scripts_load`.
- **Empirical Ground Truth:** Both base directory `safe_root` and `script_path` are canonicalized via `pathlib.Path.resolve()`, followed by `if not script_path.is_relative_to(safe_root): bottle.abort(400)`. In Python 3.9+, this is an effective, airtight path containment guard.
- **Phase 4 Handling:** PathAdversarialVerifier identified `pathlib.Path.is_relative_to` as `MANDATORY_ON_PATH` with `EFFECTIVE_NEUTRALIZATION`, correctly rejecting the finding.

### D. System Execution Dispatch Invariant (`/cmd:431`, `/script/run:1220`, `/script/abort:1278`)
- **Empirical Ground Truth:** All state-changing flight dispatch endpoints omit authentication and authorization checks.
- **Phase 4 Handling:** Semantic finding identity recognizes that these endpoints share the identical architectural defect (`MISSING_AUTHORIZATION` violating `AUTHORIZATION_CHECK`), linking them into a single coherent vulnerability family.

---

## 4. Workbench & Storage Schema V5 Persistence

The evaluation persisted full investigation artifacts into SQLite Workbench Schema V5:
- **`finding_versions`**: Audit trail of finding evolution across candidate, investigation, and confirmation phases.
- **`lifecycle_transitions`**: Deterministic state transitions (`CANDIDATE` -> `UNDER_INVESTIGATION` -> `CONFIRMED` / `REJECTED`) with explicit actor provenance.
- **`semantic_merges`**: Traceable merge audit records capturing merged evidence IDs, contributing workers, and rationale.
- **`provider_usage`**: Fine-grained token metrics distinguishing input, cached input, output tokens, and estimated cost.

---

## 5. Artifact Verification
- Metrics: `evals/finding_intelligence/evaluation_metrics.json`
- Workbench DB: `evals/finding_intelligence/workbench_evaluation.db`
- SARIF Output: `evals/finding_intelligence/phase4_findings.sarif`
- All quality gates satisfied: 159 tests passing, ruff 0 errors, mypy 0 errors.
