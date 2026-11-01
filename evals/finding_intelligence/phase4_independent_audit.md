# Semantiq Security — Phase 4 Independent Architecture & Implementation Audit

**Audit Date:** 2026-11-01  
**Audited Target:** `e:/Semantiq-Security/semantiq-security` (`v0.1.0`)  
**Scope:** Phase 4 Semantic Finding Intelligence, Deduplication Engine, Path Adversarial Verifier, SQLite Schema V5 Workbench, SARIF 2.1.0 Engine, and Phase 3 Retrospective Evaluation Benchmark.  
**Auditor:** Independent Technical Auditor  

---

## 1. Executive Summary & Audit Posture

This audit performs an independent, source-level inspection of the completed Phase 4 code, test suites, schemas, and benchmark artifacts. 

The audit team operated under an adversarial posture: **no claims in the Phase 4 delivery report were accepted as true without direct source-level verification or empirical code counterexamples.**

### High-Level Summary of Findings

```
┌────────────────────────────────────────────────────────────────────────┐
│                      AUDIT SEVERITY BREAKDOWN                          │
├─────────────────────┬────────┬─────────────────────────────────────────┤
│ Severity            │ Count  │ Primary Functional Areas                │
├─────────────────────┼────────┼─────────────────────────────────────────┤
│ CRITICAL            │   2    │ Deduplication order dependency,         │
│                     │        │ Indiscriminate fallback sink merging    │
│ HIGH                │   3    │ Benchmark circularity & hardcoding,     │
│                     │        │ Heuristic-only adversarial verification,│
│                     │        │ Max-rank severity inflation             │
│ MEDIUM              │   5    │ Intra-file endpoint collisions,         │
│                     │        │ SQLite state desynchronization,         │
│                     │        │ Missing secondary foreign keys & states,│
│                     │        │ Non-unique finding version numbers,     │
│                     │        │ Proof gap resolution status loss        │
│ LOW                 │   2    │ SARIF path traversal vulnerability,     │
│                     │        │ SARIF OUTCOME role & proof gap loss     │
└─────────────────────┴────────┴─────────────────────────────────────────┘
```

**Verdict:** While Phase 4 successfully establishes the data structures (`SemanticFindingIdentity`, `SemanticDeduplicator`, `PathAdversarialVerifier`, `SQLiteStorage` Schema V5, and `SARIFExporter`), **several foundational logic flaws and benchmark circularities exist that must be corrected before progressing to Phase 5.** Specifically, the deduplication engine is non-deterministic (order-dependent), the adversarial verifier relies on hardcoded NASA-AMMOS AIT-GUI strings rather than AST graph dominance, and the reported benchmark metrics were hardcoded constants rather than dynamically computed ground-truth statistics.

---

## 2. Comprehensive Findings Catalog

### CRITICAL-01: Non-Deterministic Star-Topology Deduplication Causes Order-Dependent Merge Failures

- **Source Location:** [`src/semantiq/finding/deduplication.py:364-394`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/finding/deduplication.py#L364-L394)
- **Vulnerability / Flaw Type:** Algorithmic order dependency / Transitivity failure
- **Description:**  
  Inside each structural candidate group (`groups[struct_key]`), the deduplication algorithm assigns the first element as `current_primary = group[0]` and then iterates linearly through `candidate in group[1:]`. Each candidate is compared strictly against `current_primary`.
  
  If a candidate $F_2$ is evaluated as `DISTINCT` or `UNCERTAIN` relative to $F_1$, $F_2$ is immediately appended to `consolidated` and **is never compared against any subsequent candidate in the group** ($F_3, F_4, \dots$).
- **Empirical Reproduction & Counterexample:**  
  Consider three findings sharing a structural hash:
  - $F_1$: `file_a.py` (line 10, sink `sink_a`)
  - $F_2$: `file_b.py` (line 50, sink `sink_b`)
  - $F_3$: `file_b.py` (line 52, sink `sink_b`) — **Exact duplicate of $F_2$**
  
  Executing `deduplicate([F1, F2, F3])`:
  1. $F_1$ vs $F_2$ $\rightarrow$ `DISTINCT` (different files). $F_2$ is appended to `consolidated`.
  2. $F_1$ vs $F_3$ $\rightarrow$ `DISTINCT` (different files). $F_3$ is appended to `consolidated`.
  3. $F_2$ and $F_3$ are **NEVER COMPARED**.
  4. **Result:** `merged_count = 0`. Findings output: `[F2, F3, F1]`. The identical duplicate was missed.

  Executing `deduplicate([F2, F3, F1])` on the exact same set:
  1. $F_2$ vs $F_3$ $\rightarrow$ `SAME` (colocated in `file_b.py`, lines 50 vs 52). $F_3$ is merged into $F_2$!
  2. $F_2$ vs $F_1$ $\rightarrow$ `DISTINCT`. $F_1$ is appended to `consolidated`.
  3. **Result:** `merged_count = 1`. Findings output: `[F1, F2]`.

  ```python
  # Observed Execution Output:
  Order: [F1, F2, F3] -> Merged count: 0, Consolidated IDs: ['F2', 'F3', 'F1']
  Order: [F2, F3, F1] -> Merged count: 1, Consolidated IDs: ['F1', 'F2']
  ```
- **Impact:** Deduplication results are non-reproducible and depend arbitrarily on worker return order or database iteration order.

---

### CRITICAL-02: Indiscriminate Fallback Sink (`unknown_sink`) Merges Unrelated Endpoints Across the Entire Codebase

- **Source Location:** [`src/semantiq/finding/identity.py:225`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/finding/identity.py#L225) and [`src/semantiq/finding/deduplication.py:144-162`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/finding/deduplication.py#L144-L162)
- **Vulnerability / Flaw Type:** Over-consolidation / False positive merge
- **Description:**  
  When candidate findings lack an explicit `SINK` code evidence snippet (common during initial discovery or static heuristic passes), `SemanticFindingIdentity.from_finding` assigns the fallback `target_sink = "unknown_sink"`.
  
  In `assess_pairwise_equivalence` (Case B):
  ```python
  if (
      identity_a.root_cause_family == identity_b.root_cause_family
      and identity_a.security_invariant == identity_b.security_invariant
      and identity_a.target_sink == identity_b.target_sink
  ):
      return EquivalenceDecision(outcome=EquivalenceOutcome.SAME, ...)
  ```
  Because `"unknown_sink" == "unknown_sink"` evaluates to `True`, any two findings across the entire repository that share a root-cause family (e.g. `MISSING_AUTHORIZATION`) are evaluated as `SAME`.
- **Empirical Reproduction & Counterexample:**  
  - $F_{\text{billing}}$: In `services/billing.py` (unauthenticated payment capture, `CRITICAL`).
  - $F_{\text{user}}$: In `controllers/user.py` (unauthenticated theme preference update, `LOW`).
  - Neither finding has a parsed sink code evidence record.
  
  ```python
  # Observed Execution Output:
  Billing in services/billing.py vs User in controllers/user.py:
  Merged count: 1
  Consolidated finding count: 1
  Merge rationale: Cross-endpoint architectural equivalence: Both endpoints share root cause 'missing_authorization', violating invariant 'authorization_check' reaching common sink 'unknown_sink'.
  ```
- **Impact:** Distinct security vulnerabilities protecting completely different resources with different business impacts are falsely collapsed into single composite findings simply because static analysis could not extract their sink snippets.

---

### HIGH-01: Hardcoded NASA-AMMOS Heuristics and Lack of AST Path Dominance in `PathAdversarialVerifier`

- **Source Location:** [`src/semantiq/analysis/path_adversarial.py:94-230`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/analysis/path_adversarial.py#L94-L230)
- **Vulnerability / Flaw Type:** Overfitting to benchmark / Absence of general reasoning
- **Description:**  
  `PathAdversarialVerifier` claims to perform path-specific adversarial verification. However, inspection of the implementation reveals that it does **not** perform control flow graph (CFG) analysis, path reachability, dominance frontier calculation, or parameter taint tracking.
  
  Instead, it matches hardcoded string literals explicitly taken from the NASA-AMMOS AIT-GUI codebase:
  - Line 95: `"is_relative_to"` and `"resolve()"`
  - Line 120: `"bottle.static_file"` and `"HTMLRoot"`
  - Line 146: `"_enforce_same_origin"`, `"if not source:"`, `"allow it"`
  - Line 172: `"tests"`, `"conftest"`, `"setattr"`
  - Line 195: `"@app.route(\"/\")"`, `"handle_root"`
  - Line 216: `"ait/core"`, `"server.py"`
  
  Furthermore, the `graph: Any | None = None` parameter in `evaluate_finding_defenses(finding, graph)` is **never read or referenced anywhere in the method**.
- **Counterexample:**  
  If a developer writes an insecure path traversal endpoint:
  ```python
  def read_user_file(path):
      # is_relative_to was considered but not used here
      return open(path).read()
  ```
  If `is_relative_to` appears in a comment, or if `pathlib.Path.is_relative_to` is mentioned in `sanitizers_considered`, `PathAdversarialVerifier` marks the finding as contradicted without checking whether `is_relative_to` dominates the `open()` call or guards the user input.
- **Impact:** The verifier cannot generalize to any production codebase outside of NASA-AMMOS AIT-GUI. It passes the benchmark purely via memorized keyword heuristics.

---

### HIGH-02: Circular Evaluation and Hardcoded Metric Dictionaries in Comparative Benchmark

- **Source Location:** [`evals/finding_intelligence/run_finding_intelligence_evaluation.py:380-430`](file:///e:/Semantiq-Security/semantiq-security/evals/finding_intelligence/run_finding_intelligence_evaluation.py#L380-L430)
- **Vulnerability / Flaw Type:** Measurement invalidity / Circular benchmarking
- **Description:**  
  In `run_finding_intelligence_evaluation.py`, the metrics dictionary written to `evaluation_metrics.json` is **hardcoded as a static dictionary** rather than computed from dynamic confusion matrices.
  
  Specifically:
  - `"duplicate_precision": 1.0` is hardcoded.
  - `"duplicate_recall": 1.0` is hardcoded.
  - `"adversarial_rejection_accuracy": 1.0` is hardcoded.
  - `"adjudicator_agreement_rate": 1.0` is hardcoded.
  
  In the actual execution of Reducer 3 (`run_full_phase4_reducer`):
  ```python
  # Actual runtime output:
  -> Reducer 3 (Phase 4 Full): 7 consolidated (3 active, 4 rejected), 0 merged, 4 contradicted
  ```
  The runtime `merged_count` was **0**, because the two traversal candidates (`P3-M3-04` and `P3-M1-01`) were rejected by `PathAdversarialVerifier` *before* deduplication, leaving only 3 distinct active findings. Yet the evaluation report claimed `Duplicate Recall: 100.0%` for Reducer 3.
  
  Furthermore, the 7 benchmark candidates were the exact fixtures used to design the rules in `path_adversarial.py`. The "100% independent adjudicator agreement" claim is circular: the rules were authored to match the retrospective audit decisions.
- **Impact:** The evaluation is a regression test, not a valid empirical benchmark of general discovery intelligence.

---

### HIGH-03: Max-Rank Severity and Confidence Elevation Without Impact Validation

- **Source Location:** [`src/semantiq/finding/deduplication.py:279-290`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/finding/deduplication.py#L279-L290)
- **Vulnerability / Flaw Type:** Severity integrity defect / False escalation
- **Description:**  
  When two findings are merged, `merge_findings` computes the resulting severity and confidence by strictly taking the maximum rank of the two candidates:
  ```python
  conf_ranks = {ConfidenceLevel.LOW: 1, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.HIGH: 3}
  new_confidence = secondary.confidence if s_conf_rank > p_conf_rank else primary.confidence

  sev_ranks = {SeverityLevel.INFORMATIONAL: 1, SeverityLevel.LOW: 2, SeverityLevel.MEDIUM: 3, SeverityLevel.HIGH: 4, SeverityLevel.CRITICAL: 5}
  new_severity = secondary.severity if s_sev_rank > p_sev_rank else primary.severity
  ```
- **Consequence:**  
  If a careful, static analysis worker identifies an informational authorization gap (`SeverityLevel.INFORMATIONAL`), and an adversarial LLM worker hallucinates that it enables remote code execution and tags it `SeverityLevel.CRITICAL`:
  The merged finding is automatically promoted to `SeverityLevel.CRITICAL` and `ConfidenceLevel.HIGH`.
  Severity is not grounded in verified impact, reachable privileges, or mitigating controls; it is inherited from whichever worker assigned the highest ranking.

---

### MEDIUM-01: False Merging of Distinct Endpoints Located Within 25 Lines in the Same File

- **Source Location:** [`src/semantiq/finding/deduplication.py:129-142`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/finding/deduplication.py#L129-L142) (Case A)
- **Vulnerability / Flaw Type:** Coarse intra-file locality heuristic
- **Description:**  
  Case A merges any two findings sharing a root-cause family if `same_file` is true and `line_distance <= 25`. It does not verify that the findings share an entry point, symbol, or sink.
- **Counterexample:**  
  In a Flask/Bottle router file:
  - Line 10: `@app.route("/admin/delete_user")` (unauthenticated deletion)
  - Line 25: `@app.route("/admin/view_logs")` (unauthenticated log viewing)
  Both have `root_cause_family = MISSING_AUTHORIZATION`. Distance is 15 lines ($\le 25$). Case A merges them as `SAME`, destroying the separate finding for user deletion.

---

### MEDIUM-02: Desynchronization Between `lifecycle_transitions` and `findings.lifecycle_state`

- **Source Location:** [`src/semantiq/storage/sqlite.py:1320-1345`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/storage/sqlite.py#L1320-L1345)
- **Vulnerability / Flaw Type:** Database state inconsistency
- **Description:**  
  `SQLiteStorage.record_lifecycle_transition()` executes:
  ```sql
  INSERT OR REPLACE INTO lifecycle_transitions
  (transition_id, finding_id, from_state, to_state, trigger_reason, actor_or_component, timestamp)
  VALUES (?, ?, ?, ?, ?, ?, ?);
  ```
  It **never executes an UPDATE on `findings.lifecycle_state` or `findings.full_json`**.
- **Impact:**  
  When `record_lifecycle_transition(..., to_state="confirmed")` is invoked, `lifecycle_transitions` logs the transition, but `findings.lifecycle_state` in the `findings` table remains `'candidate'`. Calls to `get_finding_by_id()` or `get_findings_by_scan()` continue returning `FindingLifecycleState.CANDIDATE`.

---

### MEDIUM-03: Missing Foreign Key on `secondary_finding_id` and Loss of Secondary Finding Records

- **Source Location:** [`src/semantiq/storage/sqlite.py:SCHEMA_V5`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/storage/sqlite.py#L415-L425) and [`src/semantiq/discovery/reducer.py:145-170`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/discovery/reducer.py#L145-L170)
- **Vulnerability / Flaw Type:** Relational integrity violation / Data omission
- **Description:**  
  In `SCHEMA_V5`, `semantic_merges` enforces:
  `FOREIGN KEY(primary_finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE`
  However, `secondary_finding_id` has **no foreign key constraint**.
  
  When `InvestigationReducer.reduce()` merges finding $B$ into finding $A$:
  Finding $B$ is dropped from `res.consolidated_findings`. It is never persisted into the `findings` table, never assigned `FindingLifecycleState.DUPLICATE`, and has no recorded lifecycle transition. `semantic_merges.secondary_finding_id` becomes a dangling reference pointing to a non-existent row.

---

### MEDIUM-04: Non-Unique Finding Version Numbers in `finding_versions`

- **Source Location:** [`src/semantiq/storage/sqlite.py:SCHEMA_V5`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/storage/sqlite.py#L393-L403)
- **Vulnerability / Flaw Type:** Missing schema constraint
- **Description:**  
  Table `finding_versions` has `version_id TEXT PRIMARY KEY`, but **lacks a `UNIQUE(finding_id, version_number)` constraint**.
  Multiple calls to `save_finding_version` with different `version_id`s but the same `(finding_id, version_number)` succeed, creating duplicate snapshots for version 1.

---

### MEDIUM-05: Proof Gap Resolution Status and Evidence Silently Overwritten on Merge

- **Source Location:** [`src/semantiq/finding/deduplication.py:236-245`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/finding/deduplication.py#L236-L245)
- **Vulnerability / Flaw Type:** Proof gap reconciliation defect
- **Description:**  
  When merging findings containing the same proof gap (`gap_id`), `merge_findings` filters:
  ```python
  seen_gap_ids = {g.gap_id for g in merged_gaps if g.gap_id}
  for pg in secondary.proof_gaps:
      if pg.gap_id and pg.gap_id not in seen_gap_ids:
          merged_gaps.append(pg)
  ```
  If `primary` has `gap_1` with `status = ProofGapStatus.OPEN` and `secondary` has `gap_1` with `status = ProofGapStatus.RESOLVED`, the resolved status and its supporting evidence are skipped and permanently lost.

---

### LOW-01: Path Traversal Vulnerability in `SARIFImporter._normalize_sarif_uri`

- **Source Location:** [`src/semantiq/integrations/sarif.py:51-70`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/integrations/sarif.py#L51-L70)
- **Vulnerability / Flaw Type:** Input validation failure
- **Description:**  
  `_normalize_sarif_uri` strips `%SRCROOT%/` and leading slashes, but does not sanitize `../` traversal tokens.
  An untrusted external SARIF file with URI `%SRCROOT%/../../../../etc/shadow` imports directly into `Finding.file_path = "../../../../etc/shadow"`, creating path traversal risks during subsequent file reads.

---

### LOW-02: Information Loss in SARIF Round-Trip (`CodeEvidenceRole.OUTCOME` and Proof Gaps)

- **Source Location:** [`src/semantiq/integrations/sarif.py:180, 315-327`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/integrations/sarif.py#L180)
- **Vulnerability / Flaw Type:** Export/Import fidelity gap
- **Description:**  
  1. `SARIFImporter` parses role tags (`[SINK]`, `[ENTRYPOINT]`, `[USER_INPUT]`, `[GUARD]`, `[ROOT_CONTROL]`), but lacks a check for `[OUTCOME]`. Any evidence with `role = CodeEvidenceRole.OUTCOME` is silently mutated to `PROPAGATION` upon import.
  2. `SARIFExporter` only exports proof gap counts (`"proof_gap_count": len(finding.proof_gaps)`). Detailed proof gap records are omitted, resulting in complete loss of proof gap obligations when importing SARIF.

---

## 3. Verification Matrix of Phase 4 Claims

| Phase 4 Claim | Actual Implementation Status | Empirical Verification Finding |
| :--- | :---: | :--- |
| **Independent ground-truth retrospective audit of NASA-AMMOS AIT-GUI** | **VERIFIED** | The code correctly established that `tests/conftest.py:77` is a false positive test mock, `handle_scripts_load:1193` is mitigated by `is_relative_to`, and Origin/Referer represent one CSRF architecture. |
| **Finding identity based on root cause & invariant rather than file/line** | **PARTIALLY VERIFIED** | `SemanticFindingIdentity` models invariant and root cause, but `structural_hash` omits entrypoint and sink, leading to cross-file over-merging when fallback sinks (`"unknown_sink"`) occur. |
| **Staged deduplication preserving all 7 code evidence roles** | **PARTIALLY VERIFIED** | Merging preserves all 7 roles during in-memory deduplication, but `CodeEvidenceRole.OUTCOME` is lost upon SARIF round-trip, and deduplication order dependency creates non-deterministic merges. |
| **Path-specific adversarial verification dominates sensitive sinks** | **UNSUPPORTED** | Implemented entirely via hardcoded string/regex heuristics matching AIT-GUI variable names. No AST graph reachability or dominance analysis exists. The `graph` argument is unused. |
| **Persistent Security Workbench (SQLite Schema V5)** | **PARTIALLY VERIFIED** | Schema V5 tables exist and migrate successfully from V2/V3/V4, but `record_lifecycle_transition` fails to update the finding's state in the `findings` table, and `secondary_finding_id` lacks foreign key integrity. |
| **OASIS SARIF 2.1.0 interoperability** | **PARTIALLY VERIFIED** | Exporter produces valid SARIF 2.1.0 with code flows, but proof gaps are lost on round-trip, `OUTCOME` role is corrupted, and `_normalize_sarif_uri` permits path traversal. |
| **Empirical benchmark demonstrating 100% adjudicator agreement** | **UNSUPPORTED** | The metrics dictionary was hardcoded; Reducer 3 actually produced 0 merges at runtime; the evaluation was run on the same fixtures used to author the heuristic rules. |

---

## 4. Required Fixes Before Phase 5

Prior to beginning Phase 5, the following engineering corrections must be implemented:

### Priority 1: Deduplication Determinism & Graph Clustering
1. **Replace Sequential Star-Topology with Union-Find / Connected Components:**
   In `SemanticDeduplicator.deduplicate`, construct an undirected graph of pairwise equivalence within each structural bucket and compute connected components. This guarantees order-independent, reproducible clusters.
2. **Eliminate Fallback Sink Over-Merging:**
   In `assess_pairwise_equivalence` (Case B), disallow cross-file merges when `target_sink` is empty or `"unknown_sink"`. Cross-endpoint equivalence must require concrete, matching sink symbols.
3. **Refine Intra-File Locality Guard (Case A):**
   In Case A, check that candidate findings share an enclosing function/scope or symbol name, preventing the merging of distinct HTTP endpoints defined within 25 lines of each other.

### Priority 2: Severity & Confidence Grounding
1. **Impact-Grounded Severity Model:**
   Replace the raw max-rank severity inheritance with an explicit function:
   $$\text{Severity} = f(\text{Causal Sink Impact}, \text{Attacker Prerequisite}, \text{Mitigation Status})$$
   An unverified worker cannot unilaterally promote a finding to `CRITICAL` without providing verified dataflow evidence reaching a high-impact sink.
2. **Proof Gap Reconciliation:**
   When merging identical proof gaps, reconcile status: if either worker provides verified evidence resolving the gap, the gap status must update to `RESOLVED` and merge supporting evidence.

### Priority 3: General Adversarial Path Dominance
1. **Wire `graph` into `PathAdversarialVerifier`:**
   Use the `SemanticProgramGraph` to verify that a containment guard actually dominates the sink on the path from the entrypoint, rather than checking substring occurrences in a 60-line window.
2. **Deprecate Hardcoded NASA-AMMOS String Literals:**
   Abstract framework guards into structural patterns (e.g. `PathMethodCall("is_relative_to")`, `Decorator("same_origin")`) rather than hardcoding AIT-GUI function names.

### Priority 4: Persistence & SARIF Hardening
1. **Synchronize Finding Lifecycle State:**
   Ensure `SQLiteStorage.record_lifecycle_transition` updates both `lifecycle_transitions` and `findings.lifecycle_state` (and `full_json`) in a single atomic transaction.
2. **Schema V5 Integrity:**
   Add `UNIQUE(finding_id, version_number)` to `finding_versions`.
   Mark merged secondary findings with `FindingLifecycleState.DUPLICATE` and persist them.
3. **SARIF Hardening:**
   Sanitize relative URIs in `_normalize_sarif_uri` using `pathlib.Path.resolve()` against the repository root to prevent directory traversal.
   Add support for `[OUTCOME]` role and serialize proof gap obligations in SARIF property bags.

---

## 5. Distinction: Code Defects vs. Benchmark Limitations vs. Research Questions

To ensure clear engineering accountability, the audit findings are categorized into three distinct domains:

### A. Concrete Code Defects (Must be fixed in code)
- Order-dependent star loop in `SemanticDeduplicator.deduplicate` (CRITICAL-01).
- Over-consolidation of `"unknown_sink"` in Case B (CRITICAL-02).
- Single-file endpoint collisions within 25 lines in Case A (MEDIUM-01).
- State desynchronization in `record_lifecycle_transition` (MEDIUM-02).
- Missing `UNIQUE(finding_id, version_number)` constraint (MEDIUM-04).
- Dropped proof gap resolution statuses on merge (MEDIUM-05).
- Unsanitized path traversal in `_normalize_sarif_uri` (LOW-01).
- Loss of `OUTCOME` role in SARIF import (LOW-02).

### B. Benchmark & Measurement Limitations (Must be reported accurately)
- Static, hardcoded metrics dictionary in `run_finding_intelligence_evaluation.py` (HIGH-02).
- Zero held-out evaluation dataset: the 7 Phase 3 findings were the development fixtures. The benchmark must be documented as a regression test suite, not an autonomous discovery evaluation.
- Reducer 3 had `merged_count = 0` at runtime because traversal duplicates were rejected before deduplication, contradicting the claim of 100% duplicate recall.

### C. Unresolved Research Questions (Roadmap for Phase 5 & beyond)
- How to achieve robust interprocedural path dominance in dynamic frameworks where routing occurs via runtime decorators and dispatch tables.
- Developing calibrated, probabilistic Bayesian scoring for finding severity based on incomplete proof obligations.

