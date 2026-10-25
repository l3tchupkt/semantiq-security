---
name: semantiq-security-engineering
description: Repeatable engineering and security research workflow for developing, testing, and hardening the Semantiq Security SDK, CLI, and MCP server.
---

# Semantiq Security Engineering Skill Workflow

> [!IMPORTANT]
> **Prerequisite**: Always read and adhere to [`AGENTS.md`](file:///e:/Semantiq-Security/semantiq-security/AGENTS.md) before performing any changes to the codebase. The project version must remain `0.1.0`.

This skill provides the standard, end-to-end operational procedure for working on the **Semantiq Security** platform (`semantiq`).

---

## 1. Skill Invocations & Scenarios

Use this skill whenever:
- Adding or enhancing vulnerability detection rules in AST or polyglot engines.
- Improving path validation, sandbox isolation, or trust boundary defenses.
- Implementing or extending AI provider adapters (OpenAI, Anthropic, Ollama, Mock).
- Adding or refining CLI commands or MCP tools.
- Fixing defects, improving type safety, or adding regression test fixtures.
- Generating and verifying automated unified diff remediation patches.

---

## 2. Step-by-Step Engineering Lifecycle

### Step 1: Pre-Execution Environment Baseline
Before touching any files, verify the local environment:
```powershell
# Verify git status and branch
git status
git branch --show-current

# Run baseline tests
pytest -v

# Verify code formatting and types
python -m ruff check .
python -m mypy src/semantiq
```

### Step 2: Architecture Discovery & Boundary Checks
1. Identify which layer the task affects:
   - **Scanning & Discovery**: `src/semantiq/analysis/`, `src/semantiq/discovery/`
   - **Repository & Filesystem**: `src/semantiq/repository/`
   - **Execution & Sandboxing**: `src/semantiq/sandbox/`, `src/semantiq/validation/`
   - **Remediation & Storage**: `src/semantiq/remediation/`, `src/semantiq/storage/`
   - **Interfaces**: `src/semantiq/cli.py`, `src/semantiq/integrations/mcp/`
2. **Never violate trust boundaries**:
   - Do not invoke target code in static analysis.
   - Always route filesystem operations through `resolve_safe_path()`.

### Step 3: Vulnerability Detector Development Pattern
When introducing a new vulnerability detector:
1. **Define Rule ID & Metadata**: Follow `SMTQ-<LANG>-<CATEGORY>` format (e.g. `SMTQ-PY-SQLI`, `SMTQ-JS-CMDI`).
2. **Implement AST / Pattern Visitor**:
   - Traverse the syntax tree to inspect Call nodes, argument vectors, and keyword arguments.
   - Differentiate static literals from dynamic formatting, f-strings, and tainted variables.
3. **Capture Accurate Evidence & Snippets**:
   - Extract the exact start line and end line.
   - Use `extract_context_snippet()` to capture surrounding code context for verification.
4. **Build Dual Labeled Fixtures**:
   - Add a vulnerable test case in `tests/fixtures/vulnerable_app/`.
   - Add an equivalent safe/remediated test case in `tests/fixtures/safe_app/` to prevent false positives.
5. **Add Regression Tests**:
   - Add dedicated unit tests in `tests/unit/test_python_ast.py` or `tests/unit/test_regex_patterns.py`.

### Step 4: AI Provider Adapter & Anti-Hallucination Pattern
When modifying or adding provider adapters:
1. Implement the abstract methods in `BaseAIProvider`:
   - `analyze_code(snippet, context)`
   - `propose_remediation(finding, code_context)`
2. Ensure network calls use async timeouts and clean error handling.
3. Always verify model citations using `verify_finding_citations()`:
   ```python
   is_valid, reason = verify_finding_citations(finding, repo_root)
   if not is_valid:
       # Reject or mark unverified
   ```
4. Update `MockProvider` to reflect deterministic test expectations.

### Step 5: Safe Remediation & Patch Verification
When implementing automated remediation:
1. Generate unified diffs with exact line offsets.
2. In-memory patch verification:
   - Apply patch to an in-memory buffer without modifying disk.
   - Re-parse the patched content using `ast.parse()` to verify syntax validity.
   - Re-run the AST detector to confirm that the vulnerable pattern is eliminated.

### Step 6: Full Verification Suite
Execute the full testing and quality pipeline:
```powershell
# 1. Linting
python -m ruff check .

# 2. Strict Type Check
python -m mypy src/semantiq

# 3. Unit & Integration Tests
pytest -v

# 4. Performance & Accuracy Benchmark
python benchmarks/run_benchmark.py

# 5. Build Packaging Validation
python -m build
python -m twine check dist/*
```

### Step 7: Git Staging, Review & Push
1. Inspect unstaged and staged changes:
   ```powershell
   git status
   git diff
   ```
2. Verify that NO `.env`, API keys, temporary SQLite files, or cache directories are staged.
3. Commit with conventional commit message:
   ```powershell
   git add <modified-files>
   git commit -m "feat(module): descriptive action"
   ```
4. Push to remote:
   ```powershell
   git push origin main
   ```

---

## 3. Engineering Quality Checklist

Before finalizing any task, verify:
- [ ] Version declaration across all files is strictly `0.1.0`.
- [ ] No target repository code is executed without explicit opt-in.
- [ ] Path resolution strictly prevents traversal and NTFS stream bypasses.
- [ ] No live credentials exist in fixtures, code, or logs.
- [ ] All new functions and public APIs are fully typed.
- [ ] `pytest -v` passes with 0 failures.
- [ ] `ruff check .` reports 0 errors.
- [ ] `mypy src/semantiq` reports 0 issues.
- [ ] Remote `origin/main` is up-to-date and clean.
