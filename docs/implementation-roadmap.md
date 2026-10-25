# Semantiq Security Implementation Roadmap

**Project:** Semantiq Security (`semantiq`)  
**Maintainer:** Lakshmikanthan K (`letchupkt`)  
**Status:** In Active Execution  

---

## Roadmap Stages and Deliverables

```
┌────────────────────────────────────────────────────────┐
│ Stage 1: Reconnaissance & Audit (COMPLETE)             │
│ - Codex Security architecture and license analysis     │
│ - Threat model, architecture, feature matrix docs      │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 2: Foundation & Public API                       │
│ - pyproject.toml, package structure, typed models      │
│ - Exceptions, logging, safe repository inspection      │
│ - Semantiq client facade & CLI skeleton                │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 3: Deterministic Vulnerability Discovery         │
│ - Python AST analyzer (Command, SQL, Path, SSRF, etc.) │
│ - JS/TS pattern analyzer                               │
│ - Shannon entropy & regex secret detector              │
│ - Context collector & candidate deduplication          │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 4: Codebase Threat Modeling                      │
│ - Deterministic entry point & route detection          │
│ - Trust boundary & sensitive sink mapping              │
│ - Threat model persistence & schema                    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 5: Provider-Agnostic AI Layer                    │
│ - BaseProvider interface & rate-limiting               │
│ - OpenAI, Anthropic, Ollama, & Mock adapters           │
│ - Citation & line-number verification                  │
│ - Prompt-injection isolation                           │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 6: Multi-Mode Validation Engine                  │
│ - Mode 1: Static dataflow validation                   │
│ - Mode 2: Test fixture execution                       │
│ - Mode 3: Local dynamic sandbox execution              │
│ - Mode 4: Manual reproduction plan generation          │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 7: Remediation & Patch Verification              │
│ - Unified diff generation                              │
│ - Isolated patch application & syntax checking         │
│ - Regression test verification                         │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 8: Agent Integrations & CLI                      │
│ - Model Context Protocol (MCP) server over stdio       │
│ - Full-featured Typer CLI                              │
│ - Integration guides (Claude Code, OpenCode, AGY)      │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 9: Persistence & Multi-Format Reporting          │
│ - SQLite state database with migrations                │
│ - JSON, Markdown, and SARIF 2.1.0 exporters            │
│ - Redaction of sensitive credential material           │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Stage 10: Packaging, Verification & Benchmarking       │
│ - Unit, integration, security, and e2e test suite      │
│ - Wheel build (`python -m build`) & test install       │
│ - Evaluation against vulnerable fixtures               │
└────────────────────────────────────────────────────────┘
```

---

## Milestones and Tracking

| Milestone | Target Components | Test Coverage Goal | Status |
|---|---|---|---|
| **M1: Recon & Docs** | `docs/` artifacts | N/A | **DONE** |
| **M2: Core Foundation** | `models.py`, `config.py`, `repository/`, `client.py` | Unit tests for path security & config | In Progress |
| **M3: Deterministic Analyzers** | `analysis/`, `discovery/`, `fixtures/` | Unit & integration tests for all vuln classes | Pending |
| **M4: Threat Modeling** | `threat_model/` | Route/sink extraction tests | Pending |
| **M5: AI Layer & Citation Verifier** | `providers/` | Mock provider & verification tests | Pending |
| **M6: Validation Engine** | `validation/`, `sandbox/` | 4-mode validation tests | Pending |
| **M7: Remediation & Verification** | `remediation/` | Patch diff & test re-run tests | Pending |
| **M8: CLI & MCP Server** | `cli.py`, `integrations/mcp/` | CLI smoke tests & MCP schema checks | Pending |
| **M9: Storage & Reporting** | `storage/`, `reporting/` | SQLite & SARIF 2.1.0 validation | Pending |
| **M10: Packaging & Evaluation** | `pyproject.toml`, `benchmarks/` | Full suite pass, wheel build & install | Pending |
