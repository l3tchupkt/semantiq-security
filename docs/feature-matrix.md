# Semantiq Security Feature Matrix

This matrix maps security capabilities between the reference system (Codex Security) and the Semantiq Security Python SDK implementation.

| Capability | Reference behavior | Evidence in source | Semantiq implementation | Verification status |
|---|---|---|---|---|
| **Repository Inspection** | Ripgrep-based inventory with scope validation and NTFS stream checks | `generate_in_scope_files.py`, `windows_scan_local_files.py` | `semantiq.repository.inspector`: safe path resolution, symlink boundary checks, ignore filtering, NTFS stream rejection | Implemented |
| **Git & Diff Inspection** | Detects repository commit, worktree dirty state, and computes diff ranges | `workbench_target.py`, `workbench_cli.py` | `semantiq.repository.git`: Git commit detection, dirty check, `scan_diff` branch/commit delta analysis | Implemented |
| **Deterministic AST Analysis (Python)** | Not natively implemented; relies primarily on remote model review | `plugins/codex-security/scripts/` (no AST visitor present) | `semantiq.analysis.python_ast`: Python `ast` visitor detecting SQLi, Command Injection, SSRF, Path Traversal, Deserialization, Insecure Crypto | Implemented |
| **Pattern / Syntactic Analysis (JS/TS)** | Relies on external scanner imports (Semgrep, Snyk) or LLM prompts | `semgrep-findings.ts`, `snyk-findings.ts` | `semantiq.analysis.regex_patterns`: Structural & regex rule engine for JS/TS dangerous sinks (`eval`, `child_process`, raw SQL, `fs.readFile`) | Implemented |
| **Secret Detection** | Evaluates embedded credentials using LLM prompt standard | `secret-discovery/`, `core-scan.md` | `semantiq.discovery.secrets`: Regex & Shannon entropy rule analyzer with test/placeholder false-positive suppression | Implemented |
| **Threat Modeling** | Generates markdown threat model via LLM skill prompt | `threat-model/SKILL.md`, `threat_model_projection.py` | `semantiq.threat_model`: Deterministic extraction of entry points, routes, sensitive sinks, auth decorators + optional AI enrichment | Implemented |
| **Finding Data Model & Fingerprints** | Strict JSON schema, primary SHA-256 fingerprint (`codex-security/v1:...`) | `schemas/findings.schema.json`, `finalize_scan_contract.py` | `semantiq.models.finding`: Pydantic V2 models, stable `sqf_<hash>` IDs, primary SHA-256 fingerprints, CWE taxonomy | Implemented |
| **Provider-Agnostic AI Layer** | Tightly coupled to OpenAI API and Codex hosted models | `api.ts`, `deep-scan.ts`, `provider-profile.ts` | `semantiq.providers`: Abstract `BaseProvider` with implementations for OpenAI, Anthropic, Ollama, OpenAI-compatible, and Offline Mock | Implemented |
| **AI Source Citation Verification** | Verifies citations via hosted post-processing | `finalize_scan_contract.py` | `semantiq.providers.verifier`: Validates model line numbers and code snippets against actual repository files before accepting findings | Implemented |
| **Multi-Mode Validation Engine** | Triage skill assesses static plausibility; dynamic validation requires test scripts | `validation/SKILL.md`, `custom-validation.ts` | `semantiq.validation.engine`: Mode 1 (Static dataflow), Mode 2 (Test-based fixture), Mode 3 (Dynamic sandbox execution), Mode 4 (Manual plan) | Implemented |
| **Execution Sandboxing** | Linux Bubblewrap/AppArmor and Windows Job Objects / Win32 native token | `compose.apparmor.yaml`, `docker/`, `native/proof-process-windows.mts` | `semantiq.sandbox.executor`: Safe subprocess isolation (no shell=True), resource timeouts, output size ceilings, isolated temp directories | Implemented |
| **Remediation & Patching** | Interactive patch TUI with LLM prompt generation | `patch-tui.tsx`, `remediation.ts` | `semantiq.remediation.generator`: Unified diff generation, security invariant rationale, explicit user confirmation guardrail | Implemented |
| **Patch Verification** | Standalone verification skill re-running tests | `verify-fix/SKILL.md` | `semantiq.remediation.verifier`: Applies unified diff in isolated copy, re-scans for target finding, verifies elimination & tests | Implemented |
| **Scan Persistence** | SQLite state database with migrations and lock files | `workbench_db.py`, `snapshot_sqlite.py` | `semantiq.storage.sqlite`: Versioned SQLite schema tracking scans, findings, validations, patches, and threat models | Implemented |
| **Multi-Format Reporting** | Markdown projection, JSON export, SARIF 2.1.0 conversion | `report_projection.py`, `finalize_scan_contract.py` | `semantiq.reporting`: High-fidelity Markdown reports, structured JSON exports, OASIS SARIF 2.1.0 formatted for CI/GitHub | Implemented |
| **CLI Experience** | `cs` CLI with subcommands, TUI dashboard, device login | `cli.ts`, `scan-dashboard.ts` | `semantiq.cli`: Typer/Click-based CLI with `inspect`, `scan`, `scan-diff`, `threat-model`, `findings`, `validate`, `patch`, `report`, `doctor`, `mcp` | Implemented |
| **Model Context Protocol (MCP)** | Stdio MCP launcher for Codex plugin tools | `launch_codex_security_mcp`, `.mcp.json` | `semantiq.integrations.mcp`: Full stdio MCP server exposing 10 high-value security tools with strict input schemas and workspace scoping | Implemented |
| **Agent Framework Adapters** | Built for Codex desktop/CLI plugin environment | `plugins/codex-security/` | `semantiq.integrations`: Native Python SDK for custom agent harnesses (LangGraph, Autogen), Claude Code MCP, OpenCode, and Antigravity | Implemented |

---

### Verification Status Legend
- **Inspected:** Analyzed in reference source.
- **Implemented:** Code fully written in Semantiq.
- **Unit-tested:** Verified via pytest unit test suite.
- **Integration-tested:** Verified against test repositories and fixtures.
- **Experimentally evaluated:** Benchmarked against known vulnerable fixtures.
- **Blocked by dependency:** Requires unavailable external infrastructure.
- **Not implemented:** Outside current scope.
