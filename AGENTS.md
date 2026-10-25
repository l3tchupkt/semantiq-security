# AGENTS.md — Persistent Agent Directives & Engineering Rules

## 1. Project Mission & Identity

**Semantiq Security** is an independent, production-grade Python security research SDK, CLI, and Agent integration layer.

- **Project:** Semantiq Security
- **Python Package:** `semantiq`
- **GitHub Owner:** `l3tchupkt`
- **Developer & Maintainer:** `letchupkt` (Lakshmikanthan K)
- **Commit Author Email:** `letchu.geek@gmail.com`
- **Repository Remote:** `https://github.com/l3tchupkt/semantiq-security.git`
- **Primary Branch:** `main`
- **Target Runtime:** Python 3.11+
- **Current Version:** `0.1.0`
- **License:** Apache-2.0

---

## 2. Absolute Version & Release Policy

> [!CAUTION]
> **CRITICAL NON-NEGOTIABLE RULE**: Keep Semantiq Security at version `0.1.0` throughout the entire development lifecycle.
> - Do **NOT** bump the version to `0.1.1`, `0.2.0`, `1.0.0`, or any other version.
> - Do **NOT** publish to PyPI, TestPyPI, or any package registry.
> - Do **NOT** create Git release tags.
> - Do **NOT** make the GitHub repository public.
> - Ensure all version declarations remain consistently `0.1.0` in `pyproject.toml`, `src/semantiq/__init__.py`, CLI output, and documentation.
> - A passing test suite or completed milestone is **NOT** permission to release. Only explicit authorization from `letchupkt` permits a release.

---

## 3. Architecture & Repository Layout

Semantiq Security is designed to be **offline-first, deterministic, and modular**:

```text
semantiq-security/
├── AGENTS.md                   # Persistent agent rules & engineering standards
├── SKILL.md                    # Repeatable engineering skill workflow
├── pyproject.toml              # Build, dependencies, tool configurations (Ruff, Mypy, Pytest)
├── README.md                   # Main documentation & quickstart
├── LICENSE                     # Apache-2.0
├── CHANGELOG.md                # Chronological change record (0.1.0)
├── CONTRIBUTING.md             # Contribution guidelines
├── SECURITY.md                 # Vulnerability disclosure policy
├── .gitignore                  # Strict credential, cache, and artifact exclusions
├── .github/workflows/          # GitHub Actions CI pipelines
├── docs/                       # Technical architecture, threat models, guides
├── examples/                   # Executable SDK workflow scripts
├── benchmarks/                 # Automated benchmark runners & performance metrics
├── tests/
│   ├── conftest.py             # Shared pytest fixtures & mock helpers
│   ├── fixtures/               # Labeled vulnerable & safe sample projects
│   ├── unit/                   # Component-level unit test suites
│   ├── integration/            # Full scan, CLI, and MCP protocol integration tests
│   └── security/               # Path traversal, NTFS streams, subprocess & credential tests
└── src/semantiq/               # Core SDK package
    ├── __init__.py             # Public top-level exports
    ├── client.py               # Facade orchestrator (Semantiq class)
    ├── config.py               # Pydantic configuration schemas (TOML, JSON, Env)
    ├── models.py               # Immutable Pydantic V2 data contracts & fingerprints
    ├── exceptions.py           # Structured exception hierarchy
    ├── logging.py              # Secret-scrubbing log formatters & filters
    ├── events.py               # Scan progress and diagnostic event bus
    ├── repository/
    │   ├── safepath.py         # Path traversal, symlink & NTFS alternate stream defenses
    │   ├── git.py              # Git repository introspection & diff extraction
    │   └── inspector.py        # PathSpec-based file inventory and filtering
    ├── analysis/
    │   ├── python_ast.py       # Deterministic Python AST visitor (12+ rule categories)
    │   ├── regex_patterns.py   # Polyglot structural pattern matcher (JS/TS)
    │   └── context.py          # Surrounding source code context collector
    ├── discovery/
    │   ├── secrets.py          # Shannon entropy & token regex detector with redaction
    │   └── engine.py           # Multi-stage discovery pipeline & deduplication
    ├── threat_model/
    │   └── generator.py        # Deterministic route, entrypoint & boundary extractor
    ├── providers/
    │   ├── base.py             # Abstract BaseAIProvider interface
    │   ├── verifier.py         # Source code citation & hallucination verifier
    │   ├── mock.py             # Deterministic local mock provider for offline testing
    │   ├── openai.py           # Async OpenAI adapter (httpx)
    │   ├── anthropic.py        # Async Anthropic Messages adapter (httpx)
    │   └── ollama.py           # Async local Ollama inference adapter (httpx)
    ├── sandbox/
    │   └── executor.py         # Safe subprocess execution (shell=False, env scrub)
    ├── validation/
    │   └── engine.py           # 4-mode validation engine (Static, Test, Dynamic, Manual)
    ├── remediation/
    │   ├── generator.py        # Unified diff patch proposal generator
    │   └── verifier.py         # In-memory AST patch application & syntax verifier
    ├── storage/
    │   └── sqlite.py           # SQLite persistence for scans, findings, validations
    ├── reporting/
    │   └── exporter.py         # JSON, Markdown, and OASIS SARIF 2.1.0 exporters
    ├── cli.py                  # Typer-based command-line interface
    └── integrations/
        └── mcp/server.py       # Stdio Model Context Protocol JSON-RPC 2.0 server
```

---

## 4. Engineering Standards

1. **Python 3.11+ Idioms**:
   - Use built-in type annotations (`list[str]`, `dict[str, Any]`, `Path | str`).
   - Use `asyncio` for non-blocking I/O (AI providers, MCP stdio communication).
   - Use context managers (`async with Semantiq(...) as sq:`) for resource lifecycle control.
2. **Type Safety & Linting**:
   - All code must pass `python -m ruff check .` with zero errors.
   - All code must pass `python -m mypy src/semantiq` in strict mode with zero typing errors.
   - Avoid `Any` where a specific union or generic can be defined.
3. **Decoupled Architecture**:
   - The core analysis engine (`repository`, `analysis`, `discovery`, `threat_model`, `reporting`) MUST NEVER import external AI providers or network libraries. It must remain 100% operational offline.
   - AI providers are pluggable adapters implementing `BaseAIProvider`.
   - Never import optional dependencies at module top-level if they are not in the core install.
4. **Error Handling & Resilience**:
   - Raise explicit exceptions derived from `SemantiqError` ([`src/semantiq/exceptions.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/exceptions.py)).
   - Never allow unhandled exceptions in the discovery pipeline to crash an entire scan; log non-fatal file-level errors to the event bus and continue scanning remaining files.

---

## 5. Security & Trust Boundaries

1. **Untrusted Input Invariant**:
   - All scanned repositories, configuration files, and target source trees are treated as **untrusted, potentially hostile input**.
2. **Filesystem Defense**:
   - Always resolve paths via `resolve_safe_path(base_dir, relative_path)` ([`safepath.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/repository/safepath.py)).
   - Explicitly reject path traversals (`../`), symlinks that escape the base directory, null byte injections (`\x00`), and Windows NTFS alternate data streams (`::$DATA`).
3. **Subprocess & Sandbox Execution**:
   - `shell=True` is strictly prohibited. Subprocesses must be invoked using argument sequences (`list[str]`).
   - Ordinary static scans **must never execute target code**.
   - Dynamic sandbox execution must be disabled by default (`allow_sandbox_execution=False`). It requires explicit opt-in by the user.
   - Dynamic execution on native Windows does not provide Linux cgroup/container isolation; documentation and logs must state this limitation explicitly.
4. **Credential Scrubbing & Privacy**:
   - Discovered secrets in findings or logs must be redacted using `redact_secret()` ([`logging.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/logging.py)).
   - Never write live API keys, session tokens, or private credentials into Git history, fixtures, logs, or SARIF exports.
5. **Anti-Hallucination Invariant**:
   - AI provider responses that cite file paths or line numbers must pass through `verify_finding_citations` ([`verifier.py`](file:///e:/Semantiq-Security/semantiq-security/src/semantiq/providers/verifier.py)).
   - Any finding with non-existent files or mismatched code snippets must be downgraded or rejected.

---

## 6. Git Workflow & Commit Rules

1. **Identity**:
   - `user.name`: `l3tchupkt`
   - `user.email`: `letchu.geek@gmail.com`
2. **Branching**:
   - Main branch is `main`.
3. **Commit Messages**:
   - Use conventional commit formatting:
     - `feat(scanner): add intra-procedural assignment tracking`
     - `fix(safepath): block NTFS alternate data stream bypasses`
     - `test(security): add boundary escape regression test`
     - `docs: update agent integration guidelines`
4. **Pre-Commit Verification**:
   - Run `ruff check .`
   - Run `mypy src/semantiq`
   - Run `pytest`
   - Review `git status` and `git diff` to ensure no accidental secrets or scratch files are staged.
5. **Remote Push**:
   - Push to `origin main` using `git push origin main`.
   - Never use destructive force-pushes (`git push --force`).
