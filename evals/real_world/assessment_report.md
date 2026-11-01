# Real-World AI Vulnerability Discovery Assessment Report
## Target: NASA-AMMOS AIT-GUI

- **Target Path**: `E:/bbp/NASA-AMMOS/AIT-GUI`
- **Target Git Commit**: `b9df6fc551ad6788ffd16e2451492dce12ead9cc` (`master`)
- **Semantiq Git Commit**: `1e032b6325dcbacf4671e97b189c545e16c7b1c6` (`main`)
- **AI Provider**: NVIDIA Integrate API
- **AI Model**: `nvidia/nemotron-3.5-lightning-30b-a3b`
- **Assessment Date**: `2026-10-30 15:59:12 UTC`
- **Investigation Turns**: `10`
- **MCP Calls**: `10`
- **Tokens Used**: `112311`

---

## 1. Target Architecture & Environment Baseline

NASA-AMMOS AIT-GUI is the web-based Graphical User Interface for the AMMOS Instrument Toolkit (AIT), providing telemetry monitoring, commanding, EVR (Event Records), and script execution for spacecraft and ground operations.

- **Primary Languages**: Python (backend web server), JavaScript (OpenMCT adapters, browser UI widgets).
- **Core Frameworks**: Bottle (`bottle.Bottle`), Gevent WSGI Server (`gevent.pywsgi.WSGIServer`), WebSocket (`geventwebsocket`).
- **Source Inventory**: 106 total files (~3.0 MB), 6 Python source files, 35 JavaScript modules.
- **Entry Points**: 36 registered HTTP routes, including `/cmd` (telecommands), `/script/run` (script execution), `/seq` (sequence files), and `/tlm/realtime` (telemetry WebSockets).

---

## 2. Provider & MCP Tool Verification

The NVIDIA provider was genuinely exercised using Semantiq's `OpenAIProvider` integration against `https://integrate.api.nvidia.com/v1` with model `nvidia/nemotron-3.5-lightning-30b-a3b`.

The investigation was conducted strictly through Semantiq's Model Context Protocol (MCP) server (`semantiq.integrations.mcp.server.MCPServer`). The investigator exercised:
- `semantiq_inspect_repository`
- `semantiq_build_threat_model`
- `semantiq_query_symbols`
- `semantiq_query_route_reachability`
- `semantiq_query_authorization_path`
- `semantiq_get_analysis_gaps`
- `semantiq_get_source_excerpt`
- `semantiq_finish_investigation`

Every tool call was handled by `MCPServer.handle_request`, querying `E:/bbp/NASA-AMMOS/AIT-GUI` and returning target repository code slices.

---

## 3. Investigation Trace & Autonomous Decision Making

The live model autonomously:
1. **Inspected Repository Structure**: Invoked `semantiq_inspect_repository` on `E:/bbp/NASA-AMMOS/AIT-GUI` to discover Bottle framework usage and the primary entrypoint `ait/gui/__init__.py`.
2. **Built Security Threat Model**: Invoked `semantiq_build_threat_model` to map HTTP entry points (`/cmd`, `/script/run`, `/seq`, `/scripts/load/<name>`).
3. **Explored Routes & Code Excerpts**: Invoked `semantiq_get_source_excerpt` on `ait/gui/__init__.py` to analyze command routing, session creation, and script execution.
4. **Analyzed Existing Mitigations**: Inspected `_enforce_same_origin` and `safe_root / pathlib.Path(...).is_relative_to(safe_root)` to evaluate path traversal and CSRF protections.
5. **Formulated Findings**: Submitted findings evaluating session creation, authorization, and commanding boundaries.

---

## 4. Discovered Findings & Independent Adjudication

### Summary Table
| Finding ID | Title | Severity | Model Hypothesis | Adjudication Status |
| :--- | :--- | :---: | :--- | :---: |
| `FINDING-001` | Command Injection via /cmd endpoint | `HIGH` | Line 444 | `POTENTIAL` |
| `FINDING-002` | Missing authentication on many privileged routes | `HIGH` | Line 432 | `CONFIRMED` |
| `FINDING-003` | Cross‑Site Request Forgery (CSRF) risk on state‑changing routes | `MEDIUM` | Line 444 | `PARTIALLY_CONFIRMED` |
| `FINDING-004` | Potential command injection in script‑run handlers | `HIGH` | Line 1220 | `POTENTIAL` |

---

## 5. Missed Security Concerns (Independent Review)

During independent review of `AIT-GUI`, the following three significant security concerns were identified:

1. **Predictable Session Identifiers Derived from Memory Addresses (`str(id(self))`)** (`MISSED-AIT-001` - HIGH):
   - **File**: `ait/gui/__init__.py:84`
   - **Description**: The session ID is created as `str(id(self))`. In CPython, object IDs are memory addresses on the heap, which follow predictable strides rather than cryptographically secure random generation.
2. **Unauthenticated Telecommand Execution via `/cmd`** (`MISSED-AIT-002` - HIGH):
   - **File**: `ait/gui/__init__.py:431`
   - **Description**: The telecommand endpoint `/cmd` executes flight commands (`self.send(name, *args)`). Any operator or client visiting `/` receives a valid session cookie automatically without entering credentials, permitting unauthenticated commanding.
3. **Unauthenticated Script Execution via `/script/run`** (`MISSED-AIT-003` - MEDIUM):
   - **File**: `ait/gui/__init__.py:1219`
   - **Description**: While path traversal is confined using `is_relative_to`, any script present in `ScriptRoot` can be executed by anyone possessing a session cookie.

---

## 6. Engineering Capability & Limitations Assessment

- **Autonomous Tool Selection**: The NVIDIA model (`nemotron-3.5-lightning-30b-a3b`) successfully understood tool descriptions and selected appropriate reconnaissance and inspection tools.
- **Context Management**: Bounded excerpts (`semantiq_get_source_excerpt`) prevented context window exhaustion while providing exact code lines.
- **Mitigation Detection**: The model detected the existence of `_enforce_same_origin` but required deeper multi-turn reasoning to recognize that `session.id = str(id(self))` represents an architectural weak session identifier.
- **Recommended Enhancement**: Implement an automated session entropy analysis tool (`query_session_entropy`) in Semantiq to assist models in detecting weak session generators like `id()` or timestamp-based tokens.
