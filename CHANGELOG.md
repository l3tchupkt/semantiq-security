# Changelog

All notable changes to **Semantiq Security** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-25

### Added
- Initial release of Semantiq Security SDK (`semantiq`).
- 100% Python-native architecture with `from semantiq import Semantiq` async client.
- Safe repository inspection engine with boundary verification and Windows NTFS alternate data stream defense.
- Deterministic AST visitor for Python detecting SQLi, Command Injection, SSRF, Path Traversal, Unsafe Deserialization, and Insecure Cryptography.
- JS/TS structural pattern analyzer for common dangerous sinks.
- Shannon entropy and regex-based secret detection engine with false-positive filtering for test fixtures.
- Deterministic application entry point extraction and codebase threat modeling.
- 4-mode validation engine (Static dataflow, test-based fixtures, dynamic sandbox execution, manual reproduction plan).
- Unified diff patch generation with automated verification testing in isolated temporary copies.
- Model Context Protocol (MCP) server over stdio exposing 10 security research tools.
- Typer-based CLI with `inspect`, `scan`, `scan-diff`, `threat-model`, `findings`, `validate`, `patch`, `verify-patch`, `report`, `doctor`, and `mcp`.
- SQLite scan history persistence and SARIF 2.1.0, JSON, and Markdown export capabilities.
- Unit, integration, security, and e2e test suite with controlled vulnerable test fixtures.
- Repository-wide investigation orchestrator (`InvestigationOrchestrator`) with 7-phase evidence gathering, hypothesis construction, and counterevidence evaluation.
- Architectural and logic vulnerability rules: BOLA/IDOR (`SQ-PY-013`), Missing Function-Level Auth (`SQ-PY-014`), Cross-Tenant Leakage (`SQ-PY-015`), Insecure Direct File Access (`SQ-PY-016`), and Sensitive Data Exposure (`SQ-PY-017`).
- Repository intelligence upgrade with sha256 content caching, HTTP auth boundary mapping, multi-tenant indicators, and explicit unresolved call/dynamic dispatch tracking (`UnresolvedCall`).
- Actionable coverage reporting (`CoverageReport`) with gap notes, skipped files, unparsed files, and unsupported language tracking.
- Bounded investigation budgets (`InvestigationBudget`) with call depth, files, hypotheses, model requests, and execution timeouts.
- Business Logic Flaw & State Transition Invariant rule: `SQ-PY-018` for state machine preconditions and fulfillment checks.
- Comprehensive benchmark audit with explicit instance-level ground truth matching, disclosed coverage breakdown (Semantic AST vs Polyglot scan), memory profiling, and duplicate tracking.
- Multi-tier SaaS application evaluation suite (`multitenant_saas_app` and `multitenant_saas_safe`) testing multi-hop cross-component chains.
- Multi-factor explainable prioritization scoring combining impact, reachability, attacker control, and uncertainty penalties.
- Scalability and resilience test suite covering circular imports, deep call graphs, recursive calls, and malformed syntax recovery.
- Versioned, typed Semantic Program Graph (`semantiq.graph`) with stable node identities, typed edges (`CALLS`, `PASSES_ARGUMENT`, `RETURNS_TO`, `DATA_FLOWS_TO`, `QUERIES`, `AUTHENTICATES`, `AUTHORIZES`, `CONTROLS_TENANT`, `SANITIZES`), and cycle-safe query engine.
- Language frontend abstraction (`LanguageFrontend`) supporting deep Python AST parsing and language-aware JavaScript / TypeScript semantic indexing (imports, exports, functions, Express routes, and database queries).
- Interprocedural data-flow tracing (`SPGDataFlowAnalyzer`) tracking attacker-controlled values from route parameters to sensitive sinks with context-sensitive sanitizer neutralization and tenant isolation validation.
- Expanded Model Context Protocol (MCP) suite with 10 new security analysis tools for symbol search, caller/callee lookup, bounded neighborhood extraction, route-to-sink reachability, tenant isolation inspection, analysis gap reporting, hypothesis persistence, and evidence retrieval.
- SQLite persistent repository memory (schema v2) persisting Semantic Program Graph nodes, edges, architectural summaries, and investigation hypotheses with content-hash invalidation.
- Agent Skill workflow (`SKILL.md`) rewrite providing authoritative operational procedures for graph-grounded investigation, local citation verification, and controlled remediation.

