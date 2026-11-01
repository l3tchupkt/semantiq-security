# Semantiq Security — Architecture & Execution Flow Study

## Executive Summary

This document presents a comparative visual and procedural analysis of the execution architectures of **Codex Security** and **Semantiq Security**. It traces their lifecycles across Standard, Deep, and Diff scan modes, and proposes a **Unified Target Architecture** for Semantiq Security that combines Semantiq's superior deterministic program graph with Codex's proven multi-worker reduction, evidence schema, and contract sealing models.

---

## 1. Codex Security Execution Architecture

Codex Security operates as a multi-tier hybrid agent system. The diagram below illustrates the flow from CLI invocation through parallel worker execution, SQLite state persistence, and sealed contract finalization:

```mermaid
flowchart TD
    subgraph CLI_SDK ["Client & SDK Layer"]
        CLI["CLI: cs scan / cs export / cs triage"]
        SDK["TypeScript SDK: CodexSecurity"]
        CLI --> SDK
    end

    subgraph WORKBENCH ["Workbench State & Coordination"]
        MCP["MCP Server: server.ts (31 Tools)"]
        WBScripts["Python Workbench: workbench_cli.py / workbench_db.py"]
        SQLite[(SQLite DB: 32 Normalized Tables)]
        SDK --> MCP
        MCP --> WBScripts
        WBScripts <--> SQLite
    end

    subgraph DEEP_ENGINE ["Deep Scan Coordination Engine"]
        Coord["DeepScanCoordinator (coordinator.ts)"]
        Store["WorkbenchDeepScanStore (store.ts)"]
        Coord <--> Store
        MCP --> Coord
    end

    subgraph WORKERS ["Parallel Worker Pool (fork_turns: none)"]
        W1["Discovery Worker 1: Package A"]
        W2["Discovery Worker 2: Package B"]
        W3["Discovery Worker 3: Auth & Routes"]
        Coord --> W1
        Coord --> W2
        Coord --> W3
    end

    subgraph REDUCTION ["Deduplication & Contract Sealing"]
        Reducer["Deep Scan Reducer (worker-runner.ts)"]
        DedupEngine["Embedding & Pairwise Review (deduplication.ts)"]
        Finalizer["Contract Finalizer (finalize_scan_contract.py)"]
        W1 --> Reducer
        W2 --> Reducer
        W3 --> Reducer
        Reducer --> DedupEngine
        DedupEngine --> Finalizer
    end

    subgraph ARTIFACTS ["Sealed Read-Only Artifacts"]
        SARIF["exports/results.sarif (2.1.0)"]
        FindingsJSON["exports/findings.json"]
        ThreatMD["exports/threatmodel.md"]
        Finalizer --> SARIF
        Finalizer --> FindingsJSON
        Finalizer --> ThreatMD
    end
```

---

## 2. Current Semantiq Security Execution Architecture

Semantiq Security currently relies on a single-thread linear investigation loop connecting an AI model to deterministic static analysis tools:

```mermaid
flowchart TD
    subgraph INPUT ["Target & Configuration"]
        Target["Target Repository Path"]
        Config["SemantiqConfig (v0.1.0)"]
        SafePath["SafePath Resolution (safepath.py)"]
        Target --> SafePath
    end

    subgraph STATIC_CORE ["Deterministic Static Analysis Engine"]
        Inspector["RepositoryInspector"]
        SPG["SemanticProgramGraph (builder.py)"]
        AST["Python AST Rules (python_ast.py)"]
        AsyncFlow["AsyncFlowAnalyzer (async_flow.py)"]
        DepRes["DependencyResolver (dependency_resolution.py)"]
        SecPrim["SecurityPrimitivesAnalyzer (security_primitives.py)"]
        SafePath --> Inspector
        Inspector --> SPG
        Inspector --> AST
        Inspector --> AsyncFlow
        Inspector --> DepRes
        Inspector --> SecPrim
    end

    subgraph INVESTIGATOR ["Autonomous AI Investigation Loop"]
        MCP["MCP Server & Tool Dispatcher (28 Tools)"]
        Model["AI Provider: OpenAI / NVIDIA / Mock"]
        Loop["Sequential Turn Loop (Max 14 Turns)"]
        SPG --> MCP
        AsyncFlow --> MCP
        DepRes --> MCP
        SecPrim --> MCP
        MCP <--> Loop
        Loop <--> Model
    end

    subgraph VERIFICATION ["Adjudication & Verification"]
        Verifier["CitationVerifier (verifier.py)"]
        Adjudicator["FindingAdjudicator (adjudicator.py)"]
        Loop --> Verifier
        Verifier --> Adjudicator
    end

    subgraph STORAGE ["Output & Persistence"]
        DB[(SQLiteStorage: findings, hypotheses)]
        Report["Assessment Report & Findings JSON"]
        Adjudicator --> DB
        Adjudicator --> Report
    end
```

---

## 3. Unified Target Architecture for Semantiq Security

The Unified Target Architecture merges Semantiq's deterministic code graph advantage with Codex's multi-worker coordination, rich evidence schema, and contract sealing:

```mermaid
flowchart TD
    subgraph SURFACE ["Unified Invocation Surface"]
        CLI["Semantiq CLI (semantiq scan / triage / export)"]
        SDK["Semantiq Python SDK (client.py)"]
        MCP["Semantiq MCP Server (mcp/server.py)"]
        CLI --> SDK
        MCP --> SDK
    end

    subgraph REPO_INTEL ["Deterministic Intelligence & Program Graph"]
        Safepath["SafePath Validator (safepath.py)"]
        Inspector["RepositoryInspector & Content Caching"]
        SPG["Semantic Program Graph (SPG: typed nodes & edges)"]
        Taint["SPGDataFlowAnalyzer (Interprocedural Taint)"]
        AsyncEngine["AsyncFlowAnalyzer (Queues & Workers)"]
        DepEngine["DependencyResolver (Cross-Workspace Sibling AST)"]
        PrimEngine["SecurityPrimitivesAnalyzer (Entropy & Cookies)"]
        
        SDK --> Safepath --> Inspector
        Inspector --> SPG
        SPG --> Taint
        Inspector --> AsyncEngine
        Inspector --> DepEngine
        Inspector --> PrimEngine
    end

    subgraph COORDINATION ["Multi-Worker Investigation Coordinator"]
        ThreatGen["Threat Model & Policy Generator (SECURITY.md Grounding)"]
        Packeter["Investigation Packet Partitioner"]
        Coord["InvestigationCoordinator"]
        
        SPG --> ThreatGen
        ThreatGen --> Packeter
        Packeter --> Coord
    end

    subgraph WORKERS ["Parallel Discovery Workers"]
        W1["Worker 1: Public Entrypoints & Routes"]
        W2["Worker 2: Dataflow to Sensitive Sinks"]
        W3["Worker 3: Security Primitives & Auth"]
        W4["Worker 4: Async Queues & Workers"]
        
        Coord --> W1
        Coord --> W2
        Coord --> W3
        Coord --> W4
    end

    subgraph REDUCTION ["Reduction, Deduplication & Validation"]
        Reducer["Investigation Reducer"]
        Dedup["Two-Stage Deduplication (Syntactic + LLM Pairwise)"]
        Adjudicate["FindingAdjudicator & Adversarial Skeptic"]
        ProofGap["Coverage & Proof-Gap Ledger (coverage.deferred)"]
        
        W1 --> Reducer
        W2 --> Reducer
        W3 --> Reducer
        W4 --> Reducer
        Reducer --> Dedup
        Dedup --> Adjudicate
        Adjudicate --> ProofGap
    end

    subgraph SEALING ["Contract Sealing & Enterprise Storage"]
        Finalizer["ScanContractFinalizer (finalize_contract.py)"]
        SQLite[(Workbench SQLite DB: 32 Normalized Tables)]
        SARIF["SARIF 2.1.0 Exporter (with Security Scores)"]
        Markdown["Markdown Assessment Report"]
        JSON["Findings & Coverage JSON"]
        
        Adjudicate --> Finalizer
        Finalizer --> SQLite
        Finalizer --> SARIF
        Finalizer --> Markdown
        Finalizer --> JSON
    end
```

---

## 4. Step-by-Step Lifecycle Comparison

The table below contrasts the exact step-by-step lifecycle flow between the Codex Security reference and the Semantiq Security target design:

| Lifecycle Stage | Codex Security Reference | Current Semantiq Implementation | Semantiq Target Architecture |
| :--- | :--- | :--- | :--- |
| **1. Target Specification** | Paths validated via PathSpec; git revisions hashed into `snapshotDigest`. | Paths validated via `resolve_safe_path`; protects against traversal and NTFS streams. | Combine `resolve_safe_path` with repository snapshot digest calculation for incremental caching. |
| **2. Policy & Threat Model** | Reads root/scoped `SECURITY.md`; generates structured Markdown threat model. | `ThreatModelExtractor` extracts routes and sinks; no explicit `SECURITY.md` parsing. | Integrate `SECURITY.md` resolver into `ThreatModelExtractor` to ground trust boundaries in policy. |
| **3. Packet Partitioning** | Partitions codebase into investigation packets by actor, entrypoint, and control. | Single global scope explored sequentially by one model. | Introduce `InvestigationPacketer` to divide large repositories into focused component scopes. |
| **4. Discovery Phase** | Parallel discovery workers run in sub-processes (`fork_turns: "none"`). | Single-threaded turn loop (max 14 turns) queries MCP tools. | `InvestigationCoordinator` spawns parallel discovery workers over component packets. |
| **5. Evidence Retrieval** | `ripgrep`, `git grep`, bounded source slices (`get_source_excerpt`). | SPG graph queries (`query_symbols`, `query_callers_callees`, `get_source_excerpt`). | Retain SPG graph tools and augment with bounded third-party dependency source slicing. |
| **6. Counterevidence & Proof Gaps** | Strict falsification rubric; records mitigating guards; logs missing runtime facts as Proof Gaps. | Adjudicator checks mitigations; lacks structured proof gap tracking. | Adopt Codex's Assessment Tuple ($$\text{Source}, \text{Control}, \text{Sink}, \text{Path}, \text{Boundary}, \text{Counterevidence}, \text{Proof Gaps}$$). |
| **7. Finding Deduplication** | Vector embeddings (1536d) cluster findings; LLM pairwise reviewer merges them. | Syntactic fingerprint hash (`rule_id + file + line`). | Two-stage deduplication: cluster by file/CWE/root cause, then run LLM pairwise merge. |
| **8. Contract Sealing** | 3,411-line `finalize_scan_contract.py` verifies citations on disk and seals read-only files. | `verify_finding_citations` checks local files and dependency paths. | Formalize `ScanContractFinalizer` validating JSON schemas, line bounds, and sealed manifests. |
| **9. Database Persistence** | 32 SQLite tables tracking scans, findings, locations, occurrences, triage, remediation. | 2 SQLite tables (`findings`, `hypotheses`). | Expand `SQLiteStorage` to persist complete scan runs, occurrences, coverage, and triage state. |
| **10. Reporting & Export** | SARIF 2.1.0 with security scores (9.5/8.0/5.0/2.0), CSV, Markdown, findings JSON. | JSON, Markdown, and standard SARIF export. | Update SARIF exporter with NIST/GitHub security scores and rich semantic code evidence roles. |

