# Finding Validation Engine

Semantiq Security enforces an evidence-backed validation model that separates theoretical hypotheses from verified runtime reproductions.

---

## 1. Validation Modes

### Mode 1: Static Validation (`mode="static"`)
- Inspects local source files directly.
- Confirms whether the dangerous sink is present and whether local input sanitizers (e.g., `shlex.quote`, parameterized query placeholders, HTML escaping) are absent.
- Does not execute code.

### Mode 2: Test-Based Validation (`mode="test_based"`)
- Executes targeted regression tests (e.g., `pytest -k <category>`) against a local fixture.
- Requires explicit user opt-in (`allow_execution=True`).

### Mode 3: Dynamic Sandbox Validation (`mode="dynamic_sandbox"`)
- Executes an isolated subprocess test under strict CPU timeout, memory, and output constraints.
- Requires explicit opt-in (`allow_execution=True`).

### Mode 4: Manual Validation Plan (`mode="manual_plan"`)
- Generates a concrete reproduction writeup detailing prerequisites, inputs, and expected outcomes when automated reproduction is unsafe or impractical.

---

## 2. Validation Status Taxonomy

- `unvalidated`: Initial candidate discovered by static rule or AI hypothesis.
- `validated`: Conclusively supported by static code evidence or successful test execution.
- `inconclusive`: Conflicting evidence or apparent sanitization routines present.
- `rejected`: Target file, line, or sink does not exist, or conclusive counter-evidence is verified.
