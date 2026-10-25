# Codex Security Reference Analysis

**Document Version:** 1.0.0  
**Target Project:** Semantiq Security (`semantiq`)  
**Reference Analyzed:** Codex Security (`@openai/codex-security`, commit `3d9afa7895ea54968c54e73ffceccab2396b5514`)  
**License of Reference:** Apache License 2.0 (Copyright 2025-2026 OpenAI)  
**Author:** Lakshmikanthan K (`letchupkt`)

---

## 1. Executive Summary

This document captures the architectural reconnaissance and technical audit of the Codex Security reference codebase located in the local workspace. Codex Security is a dual-language hybrid system comprising a TypeScript CLI/SDK (`@openai/codex-security`) and a Python-based workbench/plugin engine (`plugins/codex-security`), supplemented with native Rust/C++ platform sandbox bindings.

The goal of this analysis is to identify proven architectural patterns, data contracts, and security boundaries, while evaluating structural limitations and implementation gaps that **Semantiq Security** will resolve as an independent, pure-Python security research SDK.

---

## 2. Reference Architecture Overview

```
Codex Security Architecture:
┌─────────────────────────────────────────────────────────────┐
│                    CLI & TypeScript SDK                     │
│  (cs CLI, CodexSecurity SDK, Cloud Client, SARIF Exporter)  │
└───────────────┬───────────────────────────────┬─────────────┘
                │ IPC / Subprocess Calls        │
┌───────────────▼───────────────────────────────▼─────────────┐
│                   Python Workbench Backend                  │
│  - workbench_db.py (SQLite state store & scan history)      │
│  - finalize_scan_contract.py (Schema validation & sealing)  │
│  - deep_scan_workbench.py (Multi-pass worker orchestration) │
│  - windows_scan_local_files.py (Win32 API reparse checks)   │
│  - generate_in_scope_files.py (Ripgrep inventory ordering)  │
└───────────────┬─────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────┐
│             Native Sandboxing / Platform Layer              │
│  - Linux: Bubblewrap (bwrap) + AppArmor profiles            │
│  - Windows: Win32 Job Objects, Restricted Tokens, ACLs      │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 Major Modules and Responsibilities

1. **CLI and SDK (`sdk/typescript/src/`):**
   - `cli.ts`: Entry point for `cs` / `codex-security` commands (`scan`, `policy`, `export`, `validate`, `patch`, `verify-fix`, `doctor`).
   - `api.ts` & `runtime.ts`: High-level orchestration for single-pass Standard scans and multi-pass Deep scans.
   - `classify-severity.ts`: Evaluates findings against configurable severity rubrics.
   - `external-findings-*.ts`: Adapters for importing third-party findings (Snyk, Semgrep, Wiz, GitHub code scanning).
   - `patch-tui.tsx` & `remediation.ts`: Terminal user interface and workflow for inspecting and applying code fixes.

2. **Python Plugin Workbench (`plugins/codex-security/scripts/`):**
   - `workbench_db.py`: SQLite-backed state persistence tracking scan metadata, candidate findings, progress checkpoints, and coverage surfaces. Uses file-locking (`fcntl` on POSIX, `msvcrt` on Windows).
   - `finalize_scan_contract.py`: Validates JSON artifacts (`scan-manifest.json`, `findings.json`, `coverage.json`), calculates cryptographic primary fingerprints (`codex-security/v1:sha256:...`), and seals scan outputs.
   - `generate_in_scope_files.py`: Executes `rg --files` with safe scope validation and deterministic `LC_ALL=C` collation.
   - `windows_scan_local_files.py`: Implements low-level Win32 file operations (`FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_FLAG_BACKUP_SEMANTICS`) to defend against symlink/junction race conditions (TOCTOU) and NTFS alternate data streams.
   - `report_projection.py` & `threat_model_projection.py`: Render human-readable Markdown reports from sealed JSON data.

3. **Skills & Agent System (`plugins/codex-security/skills/`):**
   - 17 specialized agent skills (e.g., `security-scan`, `security-diff-scan`, `deep-security-scan`, `triage-finding`, `threat-model`, `fix-finding`, `verify-fix`).
   - Each skill defines prompt instructions, execution limits, and interaction schemas with host tools.

---

## 3. Public API Surface and Contract Models

### 3.1 Data Contracts (JSON Schemas)

Codex Security defines strict schemas for its primary deliverables:

1. **`findings.schema.json`**:
   - `findingId`: Unique string matching `^csf_[a-f0-9]{24}$`.
   - `ruleId`: Unique rule/vulnerability identifier.
   - `fingerprints`: Primary hash formatted as `codex-security/v1:sha256:<64-hex>`.
   - `severity`: Structured object with `level` (`critical`, `high`, `medium`, `low`, `informational`), optional `score`, `vector`, `rationale`.
   - `confidence`: `level` (`high`, `medium`, `low`) and `rationale`.
   - `taxonomy`: `category` and list of `cwe` identifiers.
   - `locations`: Array of file path, start line, end line, and code role.
   - `codeEvidence`: Snippets with line numbers, code, and explanations.
   - `validation`: Records `method`, `status`, `summary`, `evidenceRefs`, and `limitations`.
   - `attackPath`: Structured dataflow detailing attacker, entry point, source, sink, transformations, and reachability.

2. **`coverage.schema.json`**:
   - Explicitly records assessed surfaces, excluded files, deferred candidates, and resolved questions.
   - Prevents unproven claims of exhaustive security audits.

3. **`scan-manifest.schema.json`**:
   - Records scan configuration, target coordinates (Git revision or snapshot digest), timestamps, and artifact digests.

---

## 4. Reusable Design Patterns

The following design decisions in Codex Security represent high-grade engineering practices that Semantiq will adopt:

1. **Additive Contract & Sealed Manifests:** Scans produce structured, validated artifacts that are immutable once sealed.
2. **Defensive Path and Symlink Validation:** Strict rejection of directory escapes, symlink traversal outside repository boundaries, and NTFS alternate data streams (`filename:stream`).
3. **Evidence-Driven Validation States:** Clear taxonomy distinguishing static analysis hypotheses from verified runtime reproductions.
4. **Structured Threat Modeling:** Generating an explicit model of entry points, assets, and trust boundaries before finding discovery, rather than treating threat modeling as an afterthought.
5. **No Secret Fabrication:** Clear isolation between scanning for hardcoded secrets and testing live credentials (no external network validation of discovered API keys).

---

## 5. Architectural Limitations and Gaps in Reference

While sophisticated, the reference architecture exhibits significant limitations for broad application security research:

1. **Split-Runtime Operational Burden:** Requires Node.js 22.x+, npm, Python 3.10+, and a C++/Rust compiler for native modules. This complicates installation in Python-native research environments, Jupyter notebooks, and minimalist CI/CD runners.
2. **Heavy Cloud / LLM Backend Coupling:** The reference tool relies heavily on Codex-specific hosted models (e.g. `gpt-5.6-sol`, Daybreak programs) for its core analysis. When disconnected from OpenAI's infrastructure, its standalone vulnerability discovery capability is essentially inoperative.
3. **Absence of a Deterministic Local AST Analyzer:** The reference lacks a built-in static analysis engine (AST visitor / pattern matcher) to identify high-confidence vulnerabilities (such as SQL injection, Command injection, SSRF, Path traversal) without calling a remote LLM.
4. **No Native Python SDK:** A Python researcher cannot simply `pip install` and write `from semantiq import Semantiq` with an async Python API.
5. **Rigid Patching & Verification:** Patching in the reference relies on hosted prompt sessions rather than reproducible unified diff generation with isolated regression testing.

---

## 6. Strategic Direction for Semantiq Security

Semantiq Security will re-engineer these concepts into an independent, production-grade Python package:

- **100% Python Native:** Clean `src/semantiq` layout, installed via standard Python wheels (`pip install semantiq`).
- **Offline-First Deterministic Engine:** Full AST-based static analysis for Python and syntactic/pattern analyzers for JavaScript/TypeScript, executing instantaneously without network access or LLM credentials.
- **Pluggable AI Provider Layer:** Abstracted provider interface supporting OpenAI, Anthropic, Ollama (local LLMs), and OpenAI-compatible endpoints with rigorous prompt injection defenses and source-citation validation.
- **Comprehensive 4-Mode Validation Engine:** Static verification, test fixture execution, dynamic container execution, and manual reproduction plan generation.
- **First-Class Agent Protocols:** Built-in Model Context Protocol (MCP) server over stdio for seamless integration into Claude Code, OpenCode, and Antigravity.
- **Enterprise Reporting & Storage:** SQLite persistence, SARIF 2.1.0, JSON, and rich Markdown reporting.
