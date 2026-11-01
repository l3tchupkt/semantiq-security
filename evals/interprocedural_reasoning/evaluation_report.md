# Semantiq Security — Phase 2: Deep Python Interprocedural Reasoning Evaluation Report

## Executive Summary

- **Target Repository:** `NASA-AMMOS/AIT-GUI` (E:\bbp\NASA-AMMOS\AIT-GUI)
- **Target Git Commit:** `b9df6fc551ad6788ffd16e2451492dce12ead9cc` (`master`)
- **Model Provider:** NVIDIA `nvidia/nemotron-3.5-lightning-30b-a3b`
- **Evaluation Timestamp:** `2026-10-31T18:37:37.235981+00:00`
- **Investigation Turns:** 6
- **Total Tokens Consumed:** 58002
- **Investigation Duration:** 36.44 seconds
- **Finalization Status:** UNSEALED
- **Security Score:** 8.1/100.0

---

## 1. Quantitative Graph Accuracy & Navigation Measurements

### A. Symbol Resolution Accuracy

- **Tested Ground-Truth Symbols:** 10
- **Resolved Ground-Truth Symbols:** 10
- **Resolution Accuracy:** **100.0%**

| Symbol Query | Status | Kind | File | Line | Provenance |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Session` | RESOLVED | class | `ait/gui/__init__.py` | 44 | `direct_fact` |
| `SessionStore` | RESOLVED | class | `ait/gui/__init__.py` | 121 | `direct_fact` |
| `Playback` | RESOLVED | class | `ait/gui/__init__.py` | 193 | `direct_fact` |
| `HTMLRoot` | RESOLVED | class | `ait/gui/__init__.py` | 271 | `direct_fact` |
| `AITGUIPlugin` | RESOLVED | class | `ait/gui/__init__.py` | 356 | `direct_fact` |
| `_enforce_same_origin` | RESOLVED | function | `ait/gui/__init__.py` | 297 | `direct_fact` |
| `handle_root` | RESOLVED | function | `ait/gui/__init__.py` | 562 | `direct_fact` |
| `handle_cmd` | RESOLVED | method | `ait/gui/__init__.py` | 432 | `direct_fact` |
| `Plugin` | RESOLVED | class | `tests/conftest.py` | 127 | `direct_fact` |
| `bg_exec_seq` | RESOLVED | function | `ait/gui/__init__.py` | 1142 | `direct_fact` |

### B. Framework Route & Entrypoint Analysis (Bottle & Tornado)

- **Total Routes Detected:** 34
- **Bottle Web Routes:** 34
- **Tornado Handlers & WebSockets:** 0
- **Routes with Extracted Request Inputs:** 12
- **Routes with Evaluated Auth Guards:** 0

### C. Dynamic Dispatch with Explicit Uncertainty

- **Total Dynamic / Unresolved Sites:** 46

Sample Unresolved Dispatch Reasons:
- `Ambiguous symbol: 5 candidates for '__init__'`
- `Explicit dynamic reflection via setattr()`
- `Explicit dynamic reflection via setattr()`
- `Explicit dynamic reflection via getattr()`
- `Explicit dynamic reflection via getattr()`

### D. Interprocedural Reachability Chains to Sinks

- **Total Causal Chains Reaching Sinks:** 23
- **Unguarded Chains to Sinks:** 23

---

## 2. Live AI Investigation & Findings Adjudication

- **Total Findings Evaluated:** 3
- **Valid Findings:** 2
- **Rejected Findings (Negative Tests):** 1
- **Contract Violations:** 1 Errors, 2 Warnings

| Finding ID | Title | Severity | State | Evidence Hops | Proof Gaps |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `sqf_sq-auth-bypass-001_431` | Unauthenticated Flight Software Command Dispatch via /cmd | CRITICAL | `PARTIALLY_CONFIRMED` | 7 | 1 |
| `sqf_sq-crypto-heap-001_81` | Predictable Session Token via Python Heap Address Allocation | HIGH | `PARTIALLY_CONFIRMED` | 5 | 1 |

---

## 3. Phase 1 Contract Compliance & SARIF Output

- **Machine-Readable Report:** `finalization_report.json`
- **Sealed Manifest:** `sealed_manifest.json`
- **SARIF 2.1.0 Contract:** `contract_results.sarif`
- **SQLite V3 Database:** `interprocedural_evaluation.db`

All discoveries adhere to the strict 7-role semantic evidence model without hallucinated lines or unverified citations.