# Semantiq Security — Phase 6 Implementation Plan

**Workspace:** `e:/Semantiq-Security/semantiq-security`  
**Package Version:** `0.1.0` (Locked)  
**Date:** 2026-11-01  
**Target Revision Branch:** `main`  
**Execution Strategy:** Small, independently testable, commit-by-commit modular implementation.

---

## 1. Implementation Roadmap & Phases

### Phase 6.1: Core Skill System Infrastructure
- **Module:** `src/semantiq/skills/`
- **Files:**
  - `contract.py`: Pydantic V2 definitions for `SkillIdentifier`, `SkillCategory`, `SkillPermission`, `SkillBudget`, `SecuritySkillContract`, `SkillInputContext`, and `SkillOutput`.
  - `sandbox.py`: `SkillSandbox` enforcing filesystem isolation, point denials, write restrictions, and non-execution invariants.
  - `telemetry.py`: `SkillExecutionTelemetry` tracking provider models, token counts (input, cached, output), latency, tool calls, and transparent status.
  - `registry.py`: `SkillRegistry` providing discovery, registration, validation, topological dependency resolution, and dynamic skill selection.
- **Verification:** Unit tests covering registration, validation, dependency resolution, and permission denial.

### Phase 6.2: Operational Security Skills Implementation
- **Module:** `src/semantiq/skills/operational/`
- **Files:**
  - `base.py`: Abstract `BaseSecuritySkill` defining lifecycle methods (`execute`, `validate_inputs`, `audit_action`).
  - `threat_model.py`: `ThreatModelingSkill` mapping routes, boundaries, assets, and sinks.
  - `discovery.py`: `FindingDiscoverySkill` generating candidate findings using AST rules, SPG heuristics, and dynamic attack surfaces.
  - `attack_path.py`: `AttackPathAnalysisSkill` tracing multi-hop interprocedural paths and calibrating severity.
  - `validation.py`: `AdversarialValidationSkill` performing path-specific falsification against mitigating controls.
  - `patch_risk.py`: `PatchRiskAssessmentSkill` assessing unified diffs, contract preservation, regression risk, and auto-merge safety.
  - `verify_fix.py`: `FixVerificationSkill` verifying that an applied fix remediates a finding without regressions.
  - `scanner_ingest.py`: `ScannerIngestionSkill` ingesting and normalizing external SARIF/JSON alerts.
- **Verification:** Unit tests for each skill ensuring input validation, sandbox enforcement, and output contract conformance.

### Phase 6.3: Coordinator & Engine Integration
- **Module:** `src/semantiq/discovery/coordinator.py`, `src/semantiq/discovery/adaptive_engine.py`, `src/semantiq/discovery/reducer.py`
- **Tasks:**
  - Wire `SkillRegistry` into `InvestigationCoordinator` to select skills dynamically based on target context.
  - Enable coordinator to dispatch specialized skills to workers rather than hardcoded worker tasks.
  - Update `InvestigationReducer` to preserve skill provenance, worker identities, and execution telemetry in merged findings.
- **Verification:** Integration tests verifying end-to-end skill-driven investigation workflow.

### Phase 6.4: Evaluation & Quality Gates
- **Module:** `evals/phase6/`
- **Tasks:**
  - `phase6_evaluation_methodology.md`: Documenting evaluation methodology, held-out targets, and telemetry verification.
  - `run_phase6_evaluation.py`: Running benchmark evaluation across the 3 benchmark targets (`NASA-AMMOS/AIT-GUI`, `pyload`, `GitPython`).
  - Refresh SQLite Schema V5 workbench and SARIF report.
  - Verify all quality gates: pytest, ruff check, ruff format, mypy strict.
  - Create `evals/phase6/phase6_delivery.md`.

### Phase 6.5: Git Closure
- Commit logical, cohesive increments using Conventional Commit messages.
- Final closure commit verifying clean working tree, `letchupkt <letchu.geek@gmail.com>` author, `main` branch, and version `0.1.0`.

