# Semantiq Security — Phase 4.1 Closure Audit Evaluation Report

**Target:** NASA-AMMOS/AIT-GUI (`b9df6fc551ad6788ffd16e2451492dce12ead9cc`)  
**Date:** November 1, 2026  
**Execution Context:** Dedicated Closure Audit Metric Verification  

---

## 1. Separate Concept Analysis & Metrics

### A. Duplicate Detection (Pairwise Ground Truth)
Evaluates whether genuine duplicate findings are correctly merged.
- **Positive Pair Ground Truth:** 1 duplicate pair (`P3-M3-04`, `P3-M1-01`).
- **Reducer 1 (Naive File+Line):** TP: 1, FP: 0, FN: 0, TN: 20.
  - Recall: 1.0, Precision: 1.0.
- **Reducer 2 (Semantic Deduplicator Only):** TP: 1, FP: 0, FN: 0, TN: 20.
  - Recall: 1.0, Precision: 1.0.
- **Reducer 3 (Full Pipeline with Adversarial Verification):**
  - Note: Both `P3-M3-04` and `P3-M1-01` were proven false positives by AST path containment verification (`is_relative_to`) and contradicted *before* deduplication.
  - As required by the audit specification: *A rejected false-positive candidate must not count as a detected duplicate.*
  - Active candidate duplicates: 0 active duplicate pairs.

### B. False-Positive Rejection (Adversarial Path Verification)
Evaluates whether non-exploitable findings (test fixtures, idempotent GET routes, effective path guards) are accurately rejected.
- **Ground Truth False Positives to Reject:** 4 findings (`P3-M3-01`, `P3-M3-03`, `P3-M3-04`, `P3-M1-01`).
- **Ground Truth Genuine Flaws to Accept:** 3 findings (`P3-M3-02`, `P3-BASELINE-CMD-01`, `P3-BASELINE-SESS-02`).

| Reducer | TP (FPs Rejected) | FP (Real Flaws Rejected) | FN (FPs Missed) | TN (Real Flaws Accepted) | Rejection Accuracy | Rejection Specificity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Reducer 1 (Naive)** | 0 | 0 | 4 | 3 | 42.9% | 100.0% |
| **Reducer 2 (Semantic Only)** | 0 | 0 | 4 | 3 | 42.9% | 100.0% |
| **Reducer 3 (Full Pipeline)** | 4 | 0 | 0 | 3 | **100.0%** | **100.0%** |

### C. Overall Adjudication Agreement
- **Reducer 1 Agreement:** 42.9% (3/7)
- **Reducer 2 Agreement:** 42.9% (3/7)
- **Reducer 3 Agreement:** **100.0%** (7/7)
