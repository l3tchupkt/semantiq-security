# Codex Security Skill Architecture & Capability Parity Audit (Phase 6)

**Workspace:** `e:/Semantiq-Security/semantiq-security`  
**Reference Repository:** `e:/Semantiq-Security/codex-security`  
**Package Version:** `0.1.0` (Locked)  
**Date:** 2026-11-01  
**Author:** Semantiq Security Architecture Group  

---

## 1. Executive Summary

This study presents a rigorous reverse-engineering analysis of the **OpenAI Codex Security** skill architecture and execution harness (`plugins/codex-security/skills/`, `mcp-app/src/deep-scan/`, and `scripts/`), followed by a capability comparison against the actual implementation of **Semantiq Security** following Phase 5 completion.

Unlike earlier pre-Phase-1 snapshot comparisons, this audit accounts for Semantiq's verified capabilities as of Git commit `1fa8609` (including the typed Semantic Program Graph, interprocedural dataflow engine, asynchronous flow analyzer, 7-role evidence contract, SQLite Schema V5 workbench, parallel coordinator/reducer, and autonomous discovery engine).

### Key Architectural Findings:
1. **Nature of Codex Skills:** Codex skills are not code-level compilers or deterministic analyzers. They are structured, markdown-frontmattered prompt packages paired with OpenAI agent declarations (`agents/openai.yaml`), normative reference contracts (`references/*.md`), and tool access definitions.
2. **Execution Separation:** Codex strictly differentiates between **Top-Level Entrypoint Skills** (`security-scan`, `deep-security-scan`, `security-diff-scan`, `triage-finding`), **Staged Investigation Phase Skills** (`threat-model`, `finding-discovery`, `attack-path-analysis`, `validation`), and **Remediation / Lifecycle Skills** (`assess-patch-risk`, `fix-finding`, `verify-fix`, `track-findings`, `vulnerability-writeup`).
3. **Semantiq Parity Strategy:** Semantiq must not merely create 17 static markdown prompt files. Semantiq's evolutionary path requires a **provider-agnostic, machine-readable skill contract system** in Python, integrating deterministic graph facts, fine-grained tool sandboxing, execution telemetry, and dynamic selection into the existing coordinator and autonomous discovery engine.

---

## 2. Reverse-Engineering the 17 Codex Reference Skills

A comprehensive inspection of all 17 skills in `E:/Semantiq-Security/codex-security/plugins/codex-security/skills/` reveals their operational mechanics, triggers, inputs, outputs, and constraints.

```
codex-security/plugins/codex-security/skills/
├── assess-patch-risk/           # Patch impact, contract preservation, regression risk
├── attack-path-analysis/        # Interprocedural source-to-sink reachability & severity calibration
├── cloud-findings/              # Read-only inspection of Cloud-recorded findings
├── deep-security-scan/          # Multi-worker partitioned variance-reducing scan
├── define-security-policy/      # SECURITY.md synthesis and audit
├── finding-discovery/           # Candidate vulnerability generation from threat model
├── fix-finding/                 # Minimal surgical remediation generation
├── propose-security-hardening/  # Systemic architectural defenses
├── publish-findings/            # Finding export to Linear, Jira, Wiz
├── security-diff-scan/          # Pull-request, commit range, and git diff scan
├── security-scan/               # Standard single-pass repository scan
├── threat-model/                # Actor-boundary-entrypoint mapping
├── track-findings/              # Issue tracking & GitHub Security Advisory draft
├── triage-finding/              # External scanner alert normalization & verification
├── validation/                  # Adversarial counterevidence & falsification
├── verify-fix/                  # Read-only verification of remediation
└── vulnerability-writeup/       # Publication-ready security disclosure reporting
```

### 2.1 Complete Skill Catalog Analysis

| # | Skill Name | Primary Purpose | Trigger Conditions | Required Inputs / Context | Outputs & Artifacts | Tools & Permissions | Orchestration Role |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `assess-patch-risk` | Evaluates program impact, contract breakage, and auto-merge eligibility of a patch. | User provides a `.patch` file, PR diff, or commit range and requests risk assessment. | Target repository checkout, immutable patch/diff text. | Structured JSON risk assessment (`merge_recommendation`: `safe_to_merge`, `requires_review`, `block`), risk rubric. | Read-only filesystem access; no patch apply, edit, or git write permissions. | Independent or post-fix verification. |
| **2** | `attack-path-analysis` | Connects untrusted entry points to dangerous operations across multi-hop calls; calibrates severity. | Phase transition in `security-scan` or direct request to trace a finding. | Candidate finding, source code, call hierarchy. | Full causal attack chain (entrypoint, propagation steps, sink, preconditions). | Read-only AST / grep inspection tools; no execution. | Staged phase skill (called after discovery). |
| **3** | `cloud-findings` | Read-only inspection of Cloud-recorded security findings and scan runs. | Explicit user request to query connected cloud account or finding URL. | Connected Cloud credentials, finding ID or URL. | Formatted finding summary, triage status, verification record. | `defense_factory_*` MCP tools; read-only network access. | Standalone utility. |
| **4** | `deep-security-scan` | Multi-worker partitioned repository scan reducing variance and blind spots. | User requests deep, exhaustive, multi-pass, or variance-reducing scan. | Repository root or scoped subpath, target commit, optional user context. | Sealed `scan-manifest.json`, `findings.json`, `coverage.json`, `report.md`. | Coordinator lease tools, worker runner, SQLite workbench. | Top-level coordinator entrypoint. |
| **5** | `define-security-policy` | Synthesizes or audits `SECURITY.md` guidance based on repository architecture. | User asks to define, review, or update repository security policy. | Target source tree, existing `SECURITY.md` (if any). | Proposed `SECURITY.md` diff or markdown document. | Read-only source inspection, diff preview. | Standalone policy workflow. |
| **6** | `finding-discovery` | Identifies technically plausible security vulnerabilities across in-scope files. | Staged phase in scan or direct user discovery request. | Scoped file inventory, threat model, security policy. | Candidate findings with locations, sources, broken controls, and initial proof gaps. | File read tools, symbol search; read-only sandbox. | Staged phase skill (called by coordinator/worker). |
| **7** | `fix-finding` | Develops minimal surgical remediation patch for validated vulnerability. | Explicit user request to remediate a validated finding. | Validated finding, source files, test suite. | Unified diff patch (`.patch`), fix explanation, invariant proof. | Filesystem write to patch artifact; temporary test execution (if permitted). | Remediation lifecycle skill. |
| **8** | `propose-security-hardening` | Designs systemic architectural hardening (e.g. CSP, CSRF middleware, typing). | User requests structural defense-in-depth improvements. | Architecture summary, threat model, common vulnerability classes. | Systemic hardening blueprint, proposed architectural diffs. | Read-only source analysis, architecture inspection. | Advisory / lifecycle skill. |
| **9** | `publish-findings` | Publishes validated findings to Linear, Jira, GitHub Issues, or Wiz. | User requests external tracking export. | Validated finding IDs, external tracker credentials/config. | Issue tracking URLs, publication receipts, deduplication keys. | External tracker API clients; outbound network permission. | Post-scan publication lifecycle skill. |
| **10**| `security-diff-scan` | Analyzes code changes in PRs, commits, or git working tree. | User specifies git commit, base branch, PR number, or unstaged diff. | Base revision, head revision, diff hunk inventory. | Diff-scoped findings, regression alerts, PR summary. | `git diff`, `git show`, changed-file inventory. | Top-level entrypoint skill. |
| **11**| `security-scan` | Standard single-pass repository or scoped-path security scan. | Default repository scan request without diffs or multi-pass requirements. | Repository root or scoped subpath. | Standard canonical scan artifacts (`findings.json`, `report.md`). | Standard scan lifecycle tools, semantic checkpoints. | Top-level orchestrator entrypoint. |
| **12**| `threat-model` | Maps external actors, entry points, assets, and trust boundaries. | Phase 1 of security scan or explicit user request. | Target repository source tree, config files, route definitions. | Structured threat model (actors, boundaries, entry points, sensitive sinks). | Route discovery, AST inspection, read-only tools. | Staged phase skill (initial foundation). |
| **13**| `track-findings` | Manages finding state lifecycle across issue trackers with reviewable dry-runs. | Explicit user request to create/update issues or advisory drafts. | Validated findings, target tracker (Jira/Linear/GitHub). | Dry-run summary, created issue links, updated workbench records. | Tracker integration tools; reviewed write-access. | Lifecycle state skill. |
| **14**| `triage-finding` | Ingests, normalizes, and triages external scanner alerts (Semgrep, Snyk, Wiz). | User supplies scanner JSON/SARIF or security advisory report. | External finding payload, repository source tree. | Triage verdict (`confirmed`, `mitigated`, `false_positive`), evidence link. | SARIF parser, file reader, static verification. | Ingestion & triage entrypoint. |
| **15**| `validation` | Adversarial counterevidence search, defensive guard check, and falsification. | Phase transition following discovery or explicit finding validation request. | Candidate finding, source code, defensive helpers, tests. | Verdict (`confirmed`, `refuted`, `inconclusive`), counterevidence, resolved proof gaps. | Read-only source inspection; optional non-destructive tests. | Staged phase skill (critical falsification guard). |
| **16**| `verify-fix` | Confirms that a code change remediates a reported flaw without regressions. | User asks to verify that a patch or commit resolves a specific vulnerability. | Original finding contract, target repository with fix applied. | Verification status (`fixed`, `still_vulnerable`, `inconclusive`), proof evidence. | Read-only inspection; optional non-destructive reproducer execution. | Post-fix verification skill. |
| **17**| `vulnerability-writeup` | Converts notes, PoCs, and findings into publication-ready disclosure writeups. | User requests disclosure report, advisory draft, or bounty writeup. | Validated finding, observed behavior, proof-of-concept. | Self-contained markdown report (`findings/<slug>/<slug>.md`), PoC directory. | File export tools, markdown formatters. | Publication reporting skill. |

---

## 3. Reverse-Engineering Codex Deep Scan Infrastructure

### 3.1 Deep Scan Coordinator (`coordinator.ts`)
The Codex coordinator is responsible for:
- **Lease Acquisition & Handoff:** Uses `DeepScanCoordinatorClaim` to acquire atomic leases on a scan run. If a client detaches or the server restarts, the coordinator preserves the lease token (`handoffClaimToken`).
- **Worker Partitioning:** Partitions the repository into discrete target packages/scopes rather than dumping the entire file list onto one agent.
- **Durable Store Interface (`store.ts`):** Directly commits state changes to a local SQLite database via Python helper scripts (`deep_scan_workbench.py`).
- **Variance Reduction:** Executes multiple independent worker passes (`standard` audits) on the same scope to eliminate non-deterministic LLM blind spots.

### 3.2 Worker Runner & Packet Contracts (`worker-runner.ts`)
- Workers are invoked as independent subprocesses with strict arguments (`CodexWorkerRequest`).
- Each worker receives:
  * An isolated working directory.
  * A dedicated prompt path (`promptPath`).
  * A strict timeout signal (`AbortSignal`).
  * Immutable snapshot context (workers do not observe dynamic writes from sibling workers).
- Workers communicate results back via structured output files (`resultManifestPath`, `candidateLedgerPath`).

### 3.3 Reducer & Deduplication Commit (`coordinator.ts` / `scripts/workbench_local_dedupe.py`)
- The reducer merges candidate ledgers from completed workers.
- It applies vector clustering (`text-embedding-3-small`) combined with pairwise LLM validation.
- It commits a unified `DedupCommit` containing `newFindings`, updating the durable scan manifest.

### 3.4 Sandbox & Permission Model (`parent-sandbox.ts`)
- **Managed Permission Profiles:** Enforces `managed`, `restricted`, or `unrestricted` profiles.
- **Filesystem Denials:** Propagates explicit `filesystemDenies` (deny lists for sensitive credentials, `.env`, system files).
- **Zero-Write Invariant:** Deep scan workers **never inherit parent write access**. All worker analysis is strictly read-only.
- **Native OS Isolation:** In Windows environments, leverages Rust native bindings for process token integrity. In Linux, uses Bubblewrap/AppArmor profiles.

---

## 4. Current State Comparison: Codex Reference vs. Semantiq (Post-Phase 5)

| Architectural Domain | Codex Reference Implementation | Semantiq Security (Post-Phase 5 Baseline) | Parity Status | Key Remaining Gaps for Phase 6 |
| :--- | :--- | :--- | :--- | :--- |
| **Code Representation & Graph** | No AST compiler, no call graph, no graph DB. Relies 100% on LLM file reads and ripgrep. | Deterministic `SemanticProgramGraph` (SPG) with 7 typed nodes, 5 typed edges, AST visitor, networkx traversal. | **SEMANTIQ SUPERIOR** | None. Semantiq has deep deterministic graph capabilities Codex lacks. |
| **Interprocedural Dataflow** | Prompt-driven LLM tracing. | Deterministic `SPGDataFlowAnalyzer` with assignment tracking, return propagation, framework route awareness. | **SEMANTIQ SUPERIOR** | None. Deterministic reachability ground truth. |
| **Asynchronous Flow Analysis** | Informal narrative threat model guidelines. | Typed `AsyncFlowAnalyzer` modeling message brokers, task queues, payload propagation, worker authorization, idempotency. | **SEMANTIQ SUPERIOR** | None. Formal async modeling already built and tested. |
| **Security Primitives Analysis** | Prompt-instructed heuristics. | Deterministic `SecurityPrimitivesAnalyzer` classifying heap object session IDs (`id(self)`), CSPRNGs, weak PRNGs, cookies. | **SEMANTIQ SUPERIOR** | None. Real-world validated on NASA-AMMOS AIT-GUI. |
| **Evidence Contract & Proof Gaps** | 7 semantic roles, ordered root cause refs, `coverage.deferred` proof gaps. | Phase 1 Evidence Contract (`CodeEvidenceRole` with 7 roles, `ProofGap`, deterministic citation verifier, SARIF 2.1.0). | **PARITY ACHIEVED** | Connect evidence contracts directly into individual skill outputs. |
| **Semantic Identity & Deduplication** | Vector embedding clustering + pairwise LLM neighborhood comparison. | Deterministic `SemanticFindingIdentity` (entrypoint + vulnerability class + sink) + `SemanticDeduplicator` preserving all evidence. | **PARITY ACHIEVED** | Deterministic approach avoids vector API dependencies; achieves clean merges without evidence loss. |
| **Adversarial Validation** | Prompt-based falsification rubric in `validation/SKILL.md`. | Path-specific `PathAdversarialVerifier` evaluating sanitizers, relative path guards, and authorization checks. | **PARITY ACHIEVED** | Formalize as an independently executable skill. |
| **Workbench & State Persistence** | 32 SQLite tables tracking scans, occurrences, triage, remediation, publications. | SQLite Schema V5 with 14 normalized tables (`scans`, `findings`, `occurrences`, `evidence`, `proof_gaps`, `hypotheses`, `audit_log`). | **HIGH PARITY** | Persist skill execution telemetry, tool call counts, and per-skill token usage in workbench. |
| **Parallel Deep Scan Coordination** | `DeepScanCoordinator` in TypeScript + Python workbench CLI. | Phase 3 `InvestigationCoordinator` + `InvestigationReducer` with partitioned investigation packets. | **HIGH PARITY** | Upgrade coordinator to dynamically select specialized skills rather than fixed workers. |
| **Skill Architecture & Registry** | 17 Markdown skills + `agents/openai.yaml` + references. Loose prompt convention. | Ad-hoc worker classes (`DiscoveryWorker`, `AuthorizationWorker`, etc.). No unified skill registry or contract. | **MISSING IN SEMANTIQ** | **PRIMARY PHASE 6 TARGET:** Implement a machine-readable Python skill contract, registry, sandboxing, and dynamic selection. |
| **Patch Risk Assessment** | `assess-patch-risk/SKILL.md` with risk rubric, contract preservation, auto-merge recommendation. | Basic AST syntax patch verification (`remediation/verifier.py`). No formal semantic patch risk assessment. | **PARTIAL IN SEMANTIQ** | **PHASE 6 TARGET:** Implement `PatchRiskAssessmentSkill` with structured risk rubric and merge recommendations. |
| **Fix Verification** | `verify-fix/SKILL.md` evaluating boundary closure and non-destructive regression checks. | AST patch application verification only. | **PARTIAL IN SEMANTIQ** | **PHASE 6 TARGET:** Implement `FixVerificationSkill` with read-only boundary verification. |
| **Scanner Alert Ingestion** | `scanner-import.ts` ingesting Semgrep, Snyk, Wiz, GitHub Alerts into workbench. | Outbound SARIF exporter only. No inbound third-party alert ingestion or normalization. | **MISSING IN SEMANTIQ** | **PHASE 6 TARGET:** Implement `ScannerIngestionSkill` supporting SARIF and JSON vulnerability normalization. |
| **Provider Telemetry & Transparency** | Tracks model, tokens, cached tokens, cost, latency in SQLite. | Tracks provider tokens in basic orchestrator. Lacks structured skill-level execution telemetry. | **PARTIAL IN SEMANTIQ** | **PHASE 6 TARGET:** Implement `SkillExecutionTelemetry` recording model, input/output/cached tokens, latency, tool calls, and outcomes. |

---

## 5. Architectural Blueprint for Phase 6

To achieve true capability parity without duplicating Codex's reliance on proprietary OpenAI prompt formats, Semantiq will build a **Python-native, provider-agnostic Security Skill System**:

```
semantiq-security/src/semantiq/skills/
├── __init__.py           # Public exports (SecuritySkill, SkillRegistry, etc.)
├── contract.py           # Machine-readable skill contracts, input/output schemas, budgets
├── registry.py           # Discovery, registration, versioning, dynamic selection, dependency resolution
├── sandbox.py            # Fine-grained permission model (filesystem read/write, network, process, graph)
├── telemetry.py          # Provider-agnostic execution telemetry (tokens, latency, cost, tool calls)
└── operational/          # Real, executable, provider-agnostic security skills
    ├── discovery.py      # FindingDiscoverySkill (SQ-SKILL-DISCOVERY)
    ├── attack_path.py    # AttackPathAnalysisSkill (SQ-SKILL-ATTACK-PATH)
    ├── threat_model.py   # ThreatModelingSkill (SQ-SKILL-THREAT-MODEL)
    ├── validation.py     # AdversarialValidationSkill (SQ-SKILL-VALIDATION)
    ├── patch_risk.py     # PatchRiskAssessmentSkill (SQ-SKILL-PATCH-RISK)
    ├── verify_fix.py     # FixVerificationSkill (SQ-SKILL-VERIFY-FIX)
    └── scanner_ingest.py # ScannerIngestionSkill (SQ-SKILL-SCANNER-INGEST)
```

This architecture combines Semantiq's deterministic program analysis with Codex's modular specialization, producing a robust, auditable, and production-grade security intelligence platform.

