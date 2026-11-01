# Semantiq Security — Phase 3 Retrospective Audit Report

**Audit Target:** `NASA-AMMOS/AIT-GUI`  
**Target Commit:** `b9df6fc551ad6788ffd16e2451492dce12ead9cc` (`master`)  
**Adjudication Standard:** Ground-truth source AST inspection, runtime reachability, and cryptographic invariant verification.  
**Auditor:** Independent Security Adjudicator (Semantiq Phase 4 Audit)  

---

## 1. Executive Summary

This independent retrospective audit analyzes the candidate security findings produced during the Phase 3 comparative evaluation of Semantiq Security. 

The audit rigorously evaluates:
1. Whether `setattr()` in `tests/conftest.py` is attacker-controlled and security-relevant.
2. Whether the Origin and Referer findings are separate root causes.
3. Whether the script-loading path traversal finding is genuinely exploitable despite the previously reported path boundary guard.
4. Whether any candidate findings overlap with earlier `/cmd` authorization and session token findings.

### Summary Adjudication Table

| Candidate ID | Mode | Target Location | Reported Vulnerability | Adjudication | Root Cause Category |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **P3-M3-01** | Parallel+Adv | `tests/conftest.py:77` | Unsafe `setattr` reflection | **REJECTED** | Test fixture mock; zero attacker control |
| **P3-M3-02** | Parallel+Adv | `ait/gui/__init__.py:297` | Origin header check in `_enforce_same_origin` | **PARTIALLY CONFIRMED** | CSRF mitigation review (GHSA-4pv4-jmfm-phrw) |
| **P3-M3-03** | Parallel+Adv | `ait/gui/__init__.py:562` | Missing referer validation on `GET /` | **REJECTED** | Idempotent GET route; duplicate of P3-M3-02 |
| **P3-M3-04** | Parallel+Adv | `ait/gui/__init__.py:1193` | Script-loading path traversal | **REJECTED** | Mitigated by `is_relative_to(safe_root)` |
| **P3-M1-01** | Sequential | `ait/gui/__init__.py:1193` | Script-loading path traversal | **REJECTED** | Duplicate of P3-M3-04 |
| **P3-BASE-01**| Reference | `ait/gui/__init__.py:431` | Unauthenticated `/cmd` execution | **CONFIRMED** | Missing authorization invariant |
| **P3-BASE-02**| Reference | `ait/gui/__init__.py:81` | Weak session token heap address leak | **CONFIRMED** | Insecure PRNG / heap leak invariant |

---

## 2. In-Depth Root Cause Adjudications

### A. Dynamic Dispatch in Test Fixture (`tests/conftest.py:77`)
- **Reported finding:** `setattr(log, _level, lambda *a, **k: None)` in dynamic module initialization could allow arbitrary attribute injection.
- **Source Inspection:**
  ```python
  log = _module("ait.core.log")
  for _level in ("debug", "info", "warn", "warning", "error"):
      setattr(log, _level, lambda *a, **k: None)
  core.log = log
  ```
- **Adjudication:** **REJECTED (False Positive)**.
  1. The code is located inside `tests/conftest.py`, a pytest test harness module that is never imported or deployed in production.
  2. The `_level` variable iterates over a hardcoded tuple of literal strings.
  3. No attacker input, HTTP request, socket, or external dataflow can ever reach or influence `_level`.
  4. Flagging this was a keyword-based static analysis artifact.

### B. Origin and Referer Findings (`ait/gui/__init__.py:297` vs `ait/gui/__init__.py:562`)
- **Reported findings:**
  - Finding 1: `_enforce_same_origin` decorator lacks comprehensive CSRF token validation.
  - Finding 2: `handle_root()` on line 562 has no referer-based origin validation.
- **Source Inspection:**
  ```python
  @App.hook("before_request")
  def _enforce_same_origin():
      if bottle.request.method not in _STATE_CHANGING_METHODS:
          return
      host = bottle.request.get_header("Host")
      source = bottle.request.get_header("Origin")
      if not source:
          source = bottle.request.get_header("Referer")
      if not source:
          return
  ```
- **Adjudication:** **NOT SEPARATE ROOT CAUSES**.
  1. Both reports examine the identical CSRF mitigation architecture (`_enforce_same_origin`).
  2. The claim that `handle_root()` (line 562) lacks referer validation is invalid: `handle_root` handles `GET /` to render `index.html`. Idempotent GET views do not require CSRF protection.
  3. Furthermore, `_enforce_same_origin` explicitly inspects `Referer` when `Origin` is missing (line 318).
  4. The only genuine security question in `_enforce_same_origin` is the deliberate bypass for non-browser tooling (lines 320–323) which accepts requests when neither header is present.

### C. Script-Loading Path Traversal (`ait/gui/__init__.py:1193`)
- **Reported finding:** In `handle_scripts_load(name)`, arbitrary file traversal is possible via the `name` URL parameter.
- **Source Inspection:**
  ```python
  safe_root = pathlib.Path(ScriptRoot).resolve()
  script_path = (safe_root / pathlib.Path(urllib.parse.unquote(name))).resolve()

  if not script_path.is_relative_to(safe_root):
      bottle.abort(400, "Invalid script path")
  if not script_path.exists():
      bottle.abort(400, "Script cannot be located")

  with open(script_path) as infile:
      script_text = infile.read()
  ```
- **Adjudication:** **REJECTED (Non-Exploitable Defense Present)**.
  1. Both `safe_root` and `script_path` are resolved using `.resolve()`, which normalizes all path traversal elements (`..`) and resolves symlinks.
  2. `pathlib.Path.is_relative_to(safe_root)` strictly asserts that `safe_root` is an ancestor directory of `script_path`.
  3. If an attacker submits `../../etc/passwd`, `(safe_root / ...).resolve()` yields `/etc/passwd`. Since `/etc/passwd.is_relative_to(safe_root)` is `False`, the request is immediately aborted with HTTP 400.
  4. The path boundary guard is effective and cannot be traversed.

### D. Overlap with `/cmd`, `/script/run`, and `/script/abort`
- **Reported findings:**
  - `ait/gui/__init__.py:431`: Unauthenticated `/cmd` execution.
  - `ait/gui/__init__.py:1220/1253`: Unauthenticated `/script/run` execution.
  - `ait/gui/__init__.py:1278`: Unauthenticated `/script/abort` execution.
- **Adjudication:** **SAME ROOT CAUSE / DUPLICATE SECURITY DEFECT**.
  1. All three endpoints violate the exact same security invariant: **Missing Authentication and Principal Authorization on State-Changing Subsystem Operations**.
  2. The application architecture assumes that all callers reaching the Bottle web server are fully trusted ground station operators.
  3. Treating `/cmd`, `/script/run`, and `/script/abort` as separate, independent vulnerabilities falsely inflates finding counts when they are identical manifestations of an unauthenticated administrative control plane.

---

## 3. Retrospective Takeaways for Phase 4

1. **Title and Location are Insufficient for Finding Identity:**
   Identifying vulnerabilities by `(file_path, line_number)` fragments single architectural bugs into multiple duplicate entries (`/cmd` vs `/script/run`).
2. **Defensive Verification Must Be Path-Specific:**
   A finding should be rejected if and only if an effective guard sits directly on its causal execution path. In `handle_scripts_load`, the guard was present on the path; in `/cmd`, no guard was present.
3. **Evidence Must Be Preserved Across Equivalence Merges:**
   When consolidating `/cmd` and `/script/run`, the engine must retain both entry points and both code flows rather than discarding either.

