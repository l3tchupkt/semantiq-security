# Semantiq Security

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](pyproject.toml)
[![Architecture: Safe & Offline-First](https://img.shields.io/badge/Engine-Offline--First_AST-orange.svg)](docs/architecture.md)
[![MCP: Enabled](https://img.shields.io/badge/MCP-Compatible-purple.svg)](docs/agent-integrations.md)

**Python Security Research SDK, AI-Assisted Vulnerability Discovery Engine, and Codebase Threat Modeling Platform.**

Maintained by **Lakshmikanthan K** ([@letchupkt](https://github.com/l3tchupkt))  
Distribution: `semantiq` | Package Import: `semantiq`

---

## Key Capabilities

- **100% Offline Deterministic AST Scanning:** Discover high-impact vulnerabilities (SQLi, Command Injection, SSRF, Path Traversal, Deserialization, Insecure Crypto) using built-in Python Abstract Syntax Tree (AST) visitors and regex structural analyzers. Operates with zero network calls and no LLM API keys required.
- **Provider-Agnostic AI Layer:** Optional, pluggable enrichment supporting OpenAI, Anthropic, Ollama (local private models), and OpenAI-compatible endpoints with strict source-citation verification to eliminate hallucinations.
- **Automated Threat Modeling:** Deterministically reconstructs application entry points (HTTP routes, CLI flags), trust boundaries, and sensitive sinks from the codebase syntax.
- **4-Mode Validation Engine:** Distinguishes static evidence hypotheses from verified runtime reproductions:
  1. *Mode 1 (Static):* Verifies dataflow path and lack of sanitizers.
  2. *Mode 2 (Test-based):* Executes pytest regression tests against controlled fixtures.
  3. *Mode 3 (Dynamic Sandbox):* Isolated subprocess execution with strict user opt-in (`allow_execution=True`).
  4. *Mode 4 (Manual Plan):* Generates reproduction steps with prerequisites and proof gaps.
- **Remediation & Patch Verification:** Automatically generates unified diff patches, enforces security invariants, and verifies fixes in temporary testbeds without modifying the working tree unless approved.
- **Native Model Context Protocol (MCP):** Stdio MCP server exposing 10 security research tools for seamless integration into Claude Code, OpenCode, and Antigravity.
- **Enterprise Reporting & Persistence:** Versioned SQLite local state database with instant JSON, human-readable Markdown, and OASIS SARIF 2.1.0 exports.

---

## Installation

### Standard Installation (Core Scanner + CLI + MCP)
```bash
pip install semantiq
```

### With Optional AI Providers
```bash
pip install "semantiq[ai]"
```

### Development Setup
```bash
git clone https://github.com/l3tchupkt/semantiq-security.git
cd semantiq-security
pip install -e ".[dev]"
```

---

## Python SDK Quick Start

```python
import asyncio
from semantiq import Semantiq

async def main():
    async with Semantiq() as security:
        # Run a deterministic local audit
        result = await security.scan(
            target="./my-project",
            focus=[
                "sql-injection",
                "command-injection",
                "ssrf",
                "path-traversal",
                "hardcoded-secrets",
            ],
        )

        print(f"Scan ID: {result.scan_id}")
        print(f"Total Findings: {len(result.findings)}")

        for finding in result.findings:
            print(f"\n[{finding.severity.upper()}] {finding.title}")
            print(f"Location: {finding.file_path}:{finding.start_line}")
            print(f"Status: {finding.validation_status}")
            print(f"Remediation: {finding.remediation}")

        # Export SARIF for GitHub Code Scanning
        sarif_json = await security.export_report(result.scan_id, format="sarif")
        with open("results.sarif", "w", encoding="utf-8") as f:
            f.write(sarif_json)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Command Line Interface (CLI)

Semantiq includes a rich CLI for terminal workflows and CI/CD pipelines:

```bash
# Inspect repository layout and security scope
semantiq inspect ./my-project

# Run deterministic security audit
semantiq scan ./my-project --focus sql-injection,command-injection

# Run PR / Git diff security analysis
semantiq scan-diff ./my-project --base origin/main --head HEAD

# Generate codebase threat model
semantiq threat-model ./my-project --output threatmodel.md

# Inspect findings from a scan
semantiq findings --scan-id <SCAN_ID>

# Validate finding with Mode 1 (Static) or Mode 2 (Test-based)
semantiq validate <FINDING_ID> --mode static

# Propose unified diff patch
semantiq patch <FINDING_ID> --output fix.patch

# Verify proposed patch against tests
semantiq verify-patch <FINDING_ID> --patch-file fix.patch

# Export reports
semantiq report --scan-id <SCAN_ID> --format sarif --output results.sarif
semantiq report --scan-id <SCAN_ID> --format markdown --output report.md

# Verify local environment and tools
semantiq doctor

# Start Model Context Protocol (MCP) server
semantiq mcp
```

---

## Model Context Protocol (MCP) Integration

Semantiq includes a built-in MCP server over stdio for autonomous AI agents.

Add to your `claude_desktop_config.json` or `.mcp.json`:

```json
{
  "mcpServers": {
    "semantiq": {
      "command": "semantiq",
      "args": ["mcp"]
    }
  }
}
```

Exposed MCP Tools:
1. `semantiq_inspect_repository`
2. `semantiq_build_threat_model`
3. `semantiq_scan_repository`
4. `semantiq_scan_diff`
5. `semantiq_get_findings`
6. `semantiq_investigate_finding`
7. `semantiq_validate_finding`
8. `semantiq_propose_patch`
9. `semantiq_verify_patch`
10. `semantiq_export_report`

---

## Defensive Security Architecture

Semantiq treats scanned codebases as untrusted:
- **No Automatic Execution:** Repository code is never executed during static audits.
- **Strict Path Sandboxing:** Canonicalizes paths and rejects symlink escapes outside the repository root.
- **NTFS Stream Rejection:** Rejects Windows Alternate Data Streams (`file:stream`) and reserved DOS device names.
- **Process Isolation:** Dynamic validation commands use argument vectors (`argv: list[str]`), rejecting `shell=True`.
- **Zero Secret Transmission:** Scanned credentials and API tokens are never transmitted to external services and are redacted in exports.

---

## Documentation

- [Reference Analysis](docs/reference-analysis.md)
- [Feature Comparison Matrix](docs/feature-matrix.md)
- [SDK Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Agent Integration Guide](docs/agent-integrations.md)
- [Validation Engine Spec](docs/validation.md)
- [Security Policy](SECURITY.md)

---

## License

Apache License 2.0. Copyright 2026 Lakshmikanthan K ([@letchupkt](https://github.com/l3tchupkt)).
