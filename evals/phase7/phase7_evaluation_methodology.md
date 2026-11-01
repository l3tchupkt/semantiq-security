# Semantiq Security — Phase 7 Evaluation Methodology

**Author:** `letchupkt <letchu.geek@gmail.com>`  
**Date:** 2026-11-01  
**Semantiq Version:** `0.1.0`  
**Git Branch:** `main`  

---

## 1. Evaluation Objectives

The objective of the Phase 7 evaluation is to empirically measure the resilience, performance, and accuracy of Semantiq Security's **Deep Scan Orchestration Engine**.

Specifically, this benchmark evaluates:
1. **Orchestration Modes Comparison:** Comparing `SEQUENTIAL`, `PARALLEL` (concurrency limit = 4), and `ADAPTIVE` deep scan modes across the standard evaluation targets.
2. **Performance Bottleneck Remediation:** Measuring before-and-after runtimes for `pyload/pyload` to verify elimination of the Phase 6 32-minute bottleneck.
3. **Packet Planning & Scheduling Effectiveness:** Measuring packet generation balance, dependency resolution, and worker allocation.
4. **Fault Tolerance & Reliability:** Verifying timeout recovery, partial result preservation, and transient retry with exponential backoff + jitter.
5. **Durable Workbench Schema v6:** Validating that all scan runs, packets, state transitions, and worker execution telemetry are durably recorded in SQLite.
6. **Finding Quality & Evidence Preservation:** Confirming that parallel packet execution and reducer consolidation maintain identical or superior finding precision and recall compared to the sequential baseline without severity inflation or evidence loss.

---

## 2. Benchmark Targets & Pinned Revisions

The evaluation uses the standard ground-truth evaluation targets defined in `evals.autonomous_discovery.dataset_registry`:

| Target ID | Repository Name | Pinned Commit | Architecture | Scoped Files | Ground Truth Flaws |
|---|---|---|---|---|---|
| `nasa_ait_gui` | `NASA-AMMOS/AIT-GUI` | `b9df6fc551ad6788ffd16e2451492dce12ead9cc` | Bottle Web Application | 3 | 3 Flaws + 1 Negative Control |
| `pyload` | `pyload/pyload` | `1b12dc7f348db8c144e0f39215680415e90ca4d2` | Flask Web Application & Plugins | 358 | 3 Flaws |
| `gitpython` | `gitpython-developers/GitPython` | `3481da9618e69063464c94447167d83bd45505a9` | Library & Git CLI Wrapper | 37 | 2 Flaws |

Total scoped Python files evaluated: **398 files**.

---

## 3. Evaluated Orchestration Modes

Each target is evaluated under three distinct orchestration configurations:

1. **`SEQUENTIAL`:**
   - Single worker execution.
   - Investigation packets executed in strict topological sequence.
   - Serves as the architectural baseline.

2. **`PARALLEL`:**
   - Bounded concurrent worker execution (`concurrency_limit = 4`).
   - Independent workers process non-overlapping packets concurrently via `asyncio.Semaphore`.
   - Shared cached Semantic Program Graph (SPG) and one-pass indexed dataflow analyzer.

3. **`ADAPTIVE`:**
   - Dynamically selects worker concurrency and packet granularity based on repository scale:
     - Small targets (<10 files): Sequential mode to minimize scheduling overhead.
     - Medium targets (10-100 files): Parallel mode (`concurrency_limit = 2`).
     - Large targets (>100 files): Parallel mode (`concurrency_limit = 4`) with packet sub-partitioning by architectural dimension.

---

## 4. Controlled Evaluation Conditions

To ensure scientific rigor and repeatability:
- **Identical File Scopes:** Target subpaths and file enumeration are identical across all modes.
- **Identical Ground Truth & Rules:** Adjudication matches against ground-truth CVEs and negative controls using the established Phase 4.1/Phase 6 adjudication definitions.
- **Provider Transparency:** If model API keys are not present in the execution environment, execution status is recorded as `NOT RUN (API key not present in environment; deterministic engine benchmark evaluated)`. No mock completions or fabricated reasoning are allowed.
- **Deterministic SPG & AST Dataflow:** The same semantic program graph builder, taint tracer, and adversarial path verifier are utilized across all modes.

---

## 5. Quantitative Metrics & Reporting

The evaluation script (`evals/phase7/run_phase7_orchestration_evaluation.py`) collects and records:
- **`true_positives` (TP):** Ground-truth vulnerabilities successfully identified.
- **`false_positives` (FP):** Emitted active findings that do not correspond to verified flaws.
- **`precision` & `recall`:** $\frac{\text{TP}}{\text{TP} + \text{FP}}$ and $\frac{\text{TP}}{\text{Total Ground Truth Flaws}}$.
- **`exploit_path_completeness`:** Percentage of findings with both verified `ENTRYPOINT` and `SINK` code evidence.
- **`elapsed_seconds`:** Wall-clock time per target per mode.
- **`speedup_factor`:** Ratio of Phase 6 baseline runtime to Phase 7 runtime.
- **`packets_planned` / `packets_completed` / `packets_failed` / `packets_retried`:** Deep scan packet execution metrics.
- **`reducer_consolidation`:** Raw candidates versus deduplicated active findings.

Results are persisted to `evals/phase7/phase7_metrics.json`, `evals/phase7/phase7_findings.sarif`, and `evals/phase7/workbench_phase7.db`.

