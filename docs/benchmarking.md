# Semantiq Benchmarking and Evaluation

Semantiq includes an automated benchmark harness to measure true-positive rates, false-positive suppression, scan latency, and patch verification accuracy.

---

## 1. Running the Benchmark

```bash
python benchmarks/run_benchmark.py
```

The benchmark evaluates:
1. **Recall on Known Vulnerabilities:** Evaluates detection rate across test fixtures (`tests/fixtures/vulnerable_app`).
2. **False-Positive Suppression:** Measures false positives on secure implementations (`tests/fixtures/safe_app`).
3. **Execution Latency:** Analyzes scan time across file inventory scales.
4. **Patch Verification Accuracy:** Validates whether proposed patches eliminate findings without syntax errors.

---

## 2. Evaluation Criteria

- **True Positive (TP):** Legitimate security flaw flagged with correct line number and rule ID.
- **False Positive (FP):** Safe code or defensive implementation incorrectly flagged as vulnerable.
- **Precision:** $TP / (TP + FP)$
- **Recall:** $TP / (TP + FN)$
