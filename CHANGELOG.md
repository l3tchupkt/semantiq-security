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
