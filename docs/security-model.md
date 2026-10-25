# Semantiq Security Model & Defensive Posture

Semantiq Security is designed to operate safely even when auditing actively hostile or malicious repositories.

---

## 1. Core Defensive Rules

1. **No Automatic Code Execution:** Running a static scan (`semantiq scan`) never executes repository code, build scripts (`setup.py`), or tests.
2. **Strict Filesystem Boundaries:** All paths are resolved and validated using `relative_to(root)`. Any attempt to escape via `../` traversal or external symlinks immediately halts with a `PathTraversalError` or `SymlinkEscapeError`.
3. **NTFS Stream and Device Rejection:** Alternate data streams (`file:stream`) and reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`) are rejected.
4. **No Unsanitized Subprocesses:** When dynamic validation is opted into (`allow_execution=True`), commands use argument vectors (`argv: list[str]`), strictly forbidding `shell=True`.
5. **Secret Redaction:** Discovered credentials (AWS keys, tokens, passwords) are automatically redacted in standard reports and error logs.
6. **Zero Telemetry:** Semantiq does not transmit scan metadata, code snippets, or findings to external analytics services.
