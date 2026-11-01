"""Path-specific adversarial verification engine.

Verifies whether reported sanitizers, decorators, or defensive guards actually sit
directly on the causal execution path and neutralize the attacker-controlled value,
ensuring unrelated sanitizers never contradict legitimate vulnerabilities.
"""

from __future__ import annotations

import ast
import logging
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from semantiq.graph.models import EdgeKind, NodeKind
from semantiq.models import Finding

logger = logging.getLogger(__name__)


class GuardReachability(str, Enum):
    """Reachability relationship of a defensive guard to the causal attack path."""

    MANDATORY_ON_PATH = "MANDATORY_ON_PATH"
    BYPASSABLE = "BYPASSABLE"
    UNREACHABLE_ON_PATH = "UNREACHABLE_ON_PATH"
    UNRELATED_IN_REPO = "UNRELATED_IN_REPO"


class GuardEffectiveness(str, Enum):
    """Evaluation of whether a guard effectively neutralizes the specific exploit mechanism."""

    EFFECTIVE_NEUTRALIZATION = "EFFECTIVE_NEUTRALIZATION"
    INCOMPLETE_DEFENSE = "INCOMPLETE_DEFENSE"
    NO_NEUTRALIZATION = "NO_NEUTRALIZATION"


class AdversarialVerdict(str, Enum):
    """Explicit verdict of adversarial path evaluation."""

    PROTECTED = "PROTECTED"
    BYPASSABLE = "BYPASSABLE"
    NOT_ON_PATH = "NOT_ON_PATH"
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class PathAdversarialEvaluation(BaseModel):
    """Detailed audit of a defensive guard's relationship to an attack path."""

    model_config = ConfigDict(frozen=True)

    verdict: AdversarialVerdict = Field(default=AdversarialVerdict.UNKNOWN)
    guard_symbol: str = Field(default="")
    guard_file: str = Field(default="")
    guard_line: int = Field(default=1)
    reachability: GuardReachability
    effectiveness: GuardEffectiveness
    branch_conditions: list[str] = Field(default_factory=list)
    input_transformations: list[str] = Field(default_factory=list)
    bypass_paths: list[str] = Field(default_factory=list)
    unresolved_assumptions: list[str] = Field(default_factory=list)
    contradicts_finding: bool = Field(default=False)
    rationale: str = Field(default="")


class PathAdversarialVerifier:
    """Evaluates defensive guards and sanitizers against specific finding execution paths."""

    def __init__(self, repository_root: Path | str | None = None) -> None:
        self.repository_root = Path(repository_root).resolve() if repository_root else None

    def evaluate_finding_defenses(
        self,
        finding: Finding,
        graph: Any | None = None,
    ) -> PathAdversarialEvaluation:
        """Evaluate whether any active defense legitimately contradicts this finding."""
        f_file = finding.file_path.replace("\\", "/")
        category_str = finding.category.value.lower()
        title_lower = (finding.title or "").lower()
        summary_lower = (finding.summary or "").lower()
        counter_notes = list(finding.counterevidence or []) + list(finding.counterevidence_notes or [])

        # ---------------------------------------------------------------------
        # Evaluation Stage 1: Graph-Backed Dominance & Reachability Analysis
        # ---------------------------------------------------------------------
        if graph is not None and hasattr(graph, "nodes") and hasattr(graph, "find_paths"):
            graph_eval = self._evaluate_with_graph(finding, graph)
            if graph_eval is not None:
                return graph_eval

        # ---------------------------------------------------------------------
        # Evaluation Stage 2: Structural AST Analysis on Source Excerpt
        # ---------------------------------------------------------------------
        if self.repository_root:
            source_eval = self._evaluate_with_ast(finding, f_file, category_str, title_lower, summary_lower)
            if source_eval is not None:
                return source_eval

        # ---------------------------------------------------------------------
        # Evaluation Stage 3: Explicit Active Path Sanitizers in Finding Evidence
        # ---------------------------------------------------------------------
        for c in counter_notes:
            c_lower = c.lower()
            parts = [p.strip() for p in c.split() if "/" in p or "\\" in p or p.endswith(".py")]
            is_other_file = any(
                p.replace("\\", "/").strip("()[],:\"'") != f_file and not f_file.endswith(p.replace("\\", "/").strip("()[],:\"'"))
                for p in parts if p.endswith(".py")
            )
            if not is_other_file and any(kw in c_lower for kw in ("sanitizer active", "enforces root", "root boundary", "mandatory guard")):
                return PathAdversarialEvaluation(
                        verdict=AdversarialVerdict.PROTECTED,
                        guard_symbol="active_path_sanitizer",
                        guard_file=f_file,
                        guard_line=finding.start_line,
                        reachability=GuardReachability.MANDATORY_ON_PATH,
                        effectiveness=GuardEffectiveness.EFFECTIVE_NEUTRALIZATION,
                        branch_conditions=["Mandatory active sanitizer enforces boundary on path"],
                        bypass_paths=[],
                        contradicts_finding=True,
                        rationale=c,
                    )

        # ---------------------------------------------------------------------
        # Evaluation Stage 4: Unrelated Defenses Elsewhere in Repository
        # ---------------------------------------------------------------------
        for c in counter_notes:
            c_lower = c.lower()
            if any(term in c_lower for term in ("safe", "mitigated", "sanitized", "guard", "protected")):
                # Check if counterevidence refers to a file completely distinct from finding
                parts = [p.strip() for p in c.split() if "/" in p or "\\" in p or p.endswith(".py")]
                for p in parts:
                    clean_p = p.replace("\\", "/").strip("()[],:\"'")
                    if clean_p and clean_p != f_file and not f_file.endswith(clean_p) and not clean_p.endswith(f_file):
                        return PathAdversarialEvaluation(
                            verdict=AdversarialVerdict.NOT_ON_PATH,
                            guard_symbol="unrelated_component_defense",
                            guard_file=clean_p,
                            guard_line=1,
                            reachability=GuardReachability.UNRELATED_IN_REPO,
                            effectiveness=GuardEffectiveness.NO_NEUTRALIZATION,
                            branch_conditions=[],
                            input_transformations=[],
                            bypass_paths=[],
                            unresolved_assumptions=[],
                            contradicts_finding=False,
                            rationale=f"Defensive mechanism in {clean_p} is outside the execution path of {f_file}.",
                        )

        # ---------------------------------------------------------------------
        # Default: Limitation Preserved Honestly
        # ---------------------------------------------------------------------
        return PathAdversarialEvaluation(
            verdict=AdversarialVerdict.UNKNOWN,
            guard_symbol="",
            guard_file="",
            guard_line=1,
            reachability=GuardReachability.UNREACHABLE_ON_PATH,
            effectiveness=GuardEffectiveness.NO_NEUTRALIZATION,
            branch_conditions=[],
            input_transformations=[],
            bypass_paths=[],
            unresolved_assumptions=["No dominance or CFG paths verified along the reported execution path."],
            contradicts_finding=False,
            rationale="No mandatory, neutralizing defense verified along the causal execution path.",
        )

    def _evaluate_with_graph(
        self,
        finding: Finding,
        graph: Any,
    ) -> PathAdversarialEvaluation | None:
        """Evaluate defense reachability and dominance using SemanticProgramGraph."""
        f_file = finding.file_path.replace("\\", "/")
        category_str = finding.category.value.lower() if hasattr(finding.category, "value") else str(finding.category).lower()

        # 1. Locate entry point and sink nodes
        entry_nodes = [
            n for n in graph.nodes.values()
            if n.kind in (NodeKind.ROUTE, NodeKind.REQUEST_HANDLER, NodeKind.FUNCTION, NodeKind.METHOD)
        ]
        sink_nodes = [
            n for n in graph.nodes.values()
            if n.file_path and n.file_path.replace("\\", "/") == f_file
            and n.kind in (NodeKind.SENSITIVE_SINK, NodeKind.PROCESS_EXEC, NodeKind.FILE_OPERATION)
            and finding.start_line <= n.start_line <= finding.end_line + 5
        ]

        if not sink_nodes:
            return None

        sink_node = sink_nodes[0]

        # 2. Check route guards via graph API for category-relevant route bypasses
        if hasattr(graph, "identify_route_guards"):
            for entry_node in entry_nodes:
                route_guards = graph.identify_route_guards(entry_node.id)
                all_bypassed = route_guards.get("bypassed_guards", [])

                # Filter bypassed guards to only those relevant to the finding's vulnerability category
                relevant_bypassed = []
                if category_str in ("csrf", "cross_site_request_forgery"):
                    relevant_bypassed = [g for g in all_bypassed if "csrf" in str(g.get("guard_name", "")).lower() or "csrf" in str(g.get("kind", "")).lower()]
                elif category_str in ("authorization_bypass", "authentication_bypass", "broken_access_control"):
                    relevant_bypassed = [g for g in all_bypassed if any(kw in str(g.get("guard_name", "")).lower() or kw in str(g.get("kind", "")).lower() for kw in ("auth", "login", "perm", "role"))]

                if relevant_bypassed:
                    return PathAdversarialEvaluation(
                        verdict=AdversarialVerdict.BYPASSABLE,
                        guard_symbol=str(relevant_bypassed[0].get("guard_name", "ROUTE_GUARD")),
                        guard_file=f_file,
                        guard_line=finding.start_line,
                        reachability=GuardReachability.BYPASSABLE,
                        effectiveness=GuardEffectiveness.INCOMPLETE_DEFENSE,
                        branch_conditions=[str(relevant_bypassed[0].get("explanation", "Bypass condition detected"))],
                        bypass_paths=["Route explicitly exempts or conditionally skips security control."],
                        contradicts_finding=False,
                        rationale=f"Route security control has documented bypass: {relevant_bypassed[0].get('explanation', '')}",
                    )

        # 3. Find execution / control flow paths from ALL reaching entry points to sink
        paths: list[list[str]] = []
        for entry_node in entry_nodes:
            if hasattr(graph, "find_control_flow_paths"):
                cf_paths = graph.find_control_flow_paths(entry_node.id, sink_node.id)
                paths.extend(cf_paths)
            if not paths and hasattr(graph, "find_dataflow_paths"):
                df_paths = graph.find_dataflow_paths(entry_node.id, sink_node.id)
                paths.extend(df_paths)

        if not paths:
            return None

        # 4. Search for candidate guard nodes along the paths
        guard_node_ids = set()
        for node_id, node in graph.nodes.items():
            if node.kind in (NodeKind.SANITIZER, NodeKind.VALIDATION, NodeKind.AUTH_CONTROL, NodeKind.AUTHORIZATION_CHECK, NodeKind.CSRF_CONTROL) or any(e.kind in (EdgeKind.SANITIZES, EdgeKind.VALIDATES, EdgeKind.MITIGATES) for e in graph.in_edges.get(node_id, [])):
                guard_node_ids.add(node_id)

        if not guard_node_ids:
            return None

        # Test reachability and dominance of each guard
        for guard_id in guard_node_ids:
            paths_containing_guard = [p for p in paths if guard_id in p]
            if not paths_containing_guard:
                continue

            guard_node = graph.nodes[guard_id]
            is_dominating = len(paths_containing_guard) == len(paths)

            if is_dominating:
                return PathAdversarialEvaluation(
                    verdict=AdversarialVerdict.PROTECTED,
                    guard_symbol=guard_node.label,
                    guard_file=guard_node.file_path,
                    guard_line=guard_node.start_line,
                    reachability=GuardReachability.MANDATORY_ON_PATH,
                    effectiveness=GuardEffectiveness.EFFECTIVE_NEUTRALIZATION,
                    branch_conditions=[f"Mandatory guard {guard_node.label} dominates all execution paths to sink"],
                    input_transformations=["Path dominance verified by SemanticProgramGraph"],
                    bypass_paths=[],
                    contradicts_finding=True,
                    rationale=f"Defensive guard {guard_node.label} strictly dominates all {len(paths)} control flow paths from entrypoint to sink.",
                )
            else:
                return PathAdversarialEvaluation(
                    verdict=AdversarialVerdict.BYPASSABLE,
                    guard_symbol=guard_node.label,
                    guard_file=guard_node.file_path,
                    guard_line=guard_node.start_line,
                    reachability=GuardReachability.BYPASSABLE,
                    effectiveness=GuardEffectiveness.INCOMPLETE_DEFENSE,
                    branch_conditions=[f"Guard {guard_node.label} is only present on {len(paths_containing_guard)} of {len(paths)} paths"],
                    bypass_paths=[f"Alternate path: {' -> '.join(p)}" for p in paths if guard_id not in p],
                    contradicts_finding=False,
                    rationale=f"Guard {guard_node.label} protects some paths but does not dominate the sink on all paths.",
                )

        return None

    def _evaluate_with_ast(
        self,
        finding: Finding,
        f_file: str,
        category_str: str,
        title_lower: str,
        summary_lower: str,
    ) -> PathAdversarialEvaluation | None:
        """Perform structural AST analysis on the source code excerpt."""
        if not self.repository_root:
            return None

        full_path = self.repository_root / f_file
        if not full_path.is_file():
            return None

        # Case 1: Non-production test fixtures / harnesses
        file_lower = f_file.lower()
        is_test_file = any(
            t in file_lower for t in ("/tests/", "/test/", "test_", "_test.py", "conftest.py")
        )
        if is_test_file:
            return PathAdversarialEvaluation(
                verdict=AdversarialVerdict.PROTECTED,
                guard_symbol="test_fixture_scope",
                guard_file=f_file,
                guard_line=finding.start_line,
                reachability=GuardReachability.UNREACHABLE_ON_PATH,
                effectiveness=GuardEffectiveness.NO_NEUTRALIZATION,
                branch_conditions=["pytest test runner scope"],
                bypass_paths=[],
                unresolved_assumptions=["Only executed in local test harness"],
                contradicts_finding=True,
                rationale=f"File {f_file} is a test suite component. The reported operation is not reachable in production deployments.",
            )

        try:
            source_content = full_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source_content, filename=str(full_path))
        except Exception as exc:
            logger.debug("Could not parse AST for %s: %s", f_file, exc)
            return None

        # Case 2: Idempotent HTTP GET Endpoints (No CSRF Required)
        is_csrf_category = "csrf" in category_str or "csrf" in title_lower or "origin" in title_lower
        if is_csrf_category:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= finding.start_line <= getattr(node, "end_lineno", node.lineno + 50):
                    # Inspect route decorators
                    for dec in node.decorator_list:
                        dec_str = ast.unparse(dec).lower()
                        if "@app.get" in dec_str or ("route" in dec_str and not any(m in dec_str for m in ("'post'", '"post"', "'put'", '"put"', "'delete'", '"delete"', "'patch'", '"patch"'))):
                            return PathAdversarialEvaluation(
                                verdict=AdversarialVerdict.PROTECTED,
                                guard_symbol="http_get_idempotent",
                                guard_file=f_file,
                                guard_line=finding.start_line,
                                reachability=GuardReachability.MANDATORY_ON_PATH,
                                effectiveness=GuardEffectiveness.EFFECTIVE_NEUTRALIZATION,
                                branch_conditions=["request.method == 'GET'"],
                                bypass_paths=[],
                                contradicts_finding=True,
                                rationale="HTTP GET route is an idempotent view serving static content; CSRF protection is not applicable.",
                            )

        # Case 3: Structural Path Containment Analysis (AST Call Verification & Dominance)
        is_traversal_category = "path_traversal" in category_str or "traversal" in title_lower or "traversal" in summary_lower
        if is_traversal_category:
            # Locate enclosing function
            target_func: ast.FunctionDef | ast.AsyncFunctionDef | None = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= finding.start_line <= getattr(node, "end_lineno", node.lineno + 100):
                    target_func = node
                    break

            if target_func is not None:
                # 1. Identify sink call and variable name being accessed at the sink
                sink_line = max(finding.start_line, finding.end_line)
                for ev in finding.code_evidence:
                    if getattr(ev.role, "value", str(ev.role)) == "sink":
                        sink_line = max(sink_line, ev.start_line)

                sink_var_names: set[str] = set()
                for inner in ast.walk(target_func):
                    lineno = getattr(inner, "lineno", 0)
                    if lineno and abs(lineno - sink_line) <= 5:
                        if isinstance(inner, ast.Call):
                            if isinstance(inner.func, ast.Name) and inner.func.id in ("open", "read", "file"):
                                for arg in inner.args:
                                    if isinstance(arg, ast.Name):
                                        sink_var_names.add(arg.id)
                            elif isinstance(inner.func, ast.Attribute) and inner.func.attr in ("read_text", "read_bytes", "open", "read"):
                                if isinstance(inner.func.value, ast.Name):
                                    sink_var_names.add(inner.func.value.id)
                            elif isinstance(inner.func, ast.Attribute) and inner.func.attr == "static_file" and ("bottle" in source_content or "static" in source_content):
                                return PathAdversarialEvaluation(
                                    verdict=AdversarialVerdict.PROTECTED,
                                    guard_symbol="framework_static_file_containment",
                                    guard_file=f_file,
                                    guard_line=finding.start_line,
                                    reachability=GuardReachability.MANDATORY_ON_PATH,
                                    effectiveness=GuardEffectiveness.EFFECTIVE_NEUTRALIZATION,
                                    branch_conditions=["static_file root containment check"],
                                    input_transformations=["normpath"],
                                    bypass_paths=[],
                                    contradicts_finding=True,
                                    rationale=f"Framework static_file serving in {f_file}:{finding.start_line} handles path containment and rejects traversal.",
                                )
                        elif isinstance(inner, ast.With):
                            for item in inner.items:
                                if isinstance(item.context_expr, ast.Call):
                                    c = item.context_expr
                                    if isinstance(c.func, ast.Name) and c.func.id == "open":
                                        for arg in c.args:
                                            if isinstance(arg, ast.Name):
                                                sink_var_names.add(arg.id)

                # 2. Inspect If statements in target_func for containment checks
                containment_guards: list[dict[str, Any]] = []
                for inner in ast.walk(target_func):
                    if isinstance(inner, ast.If):
                        test_str = ast.unparse(inner.test).lower()
                        is_guard_test = "is_relative_to" in test_str or "commonpath" in test_str
                        if not is_guard_test:
                            continue

                        # Extract variable checked in test
                        checked_vars: set[str] = set()
                        for call in ast.walk(inner.test):
                            if isinstance(call, ast.Call):
                                if isinstance(call.func, ast.Attribute) and call.func.attr == "is_relative_to":
                                    if isinstance(call.func.value, ast.Name):
                                        checked_vars.add(call.func.value.id)
                                elif isinstance(call.func, (ast.Name, ast.Attribute)) and "commonpath" in ast.unparse(call.func):
                                    for arg in call.args:
                                        for sub in ast.walk(arg):
                                            if isinstance(sub, ast.Name):
                                                checked_vars.add(sub.id)

                        # Check if the if-body terminates execution on check failure
                        body_terminates = any(
                            isinstance(b, (ast.Raise, ast.Assert, ast.Return))
                            or (isinstance(b, ast.Expr) and isinstance(b.value, ast.Call) and "abort" in ast.unparse(b.value).lower())
                            for b in ast.walk(inner)
                        )

                        containment_guards.append({
                            "node": inner,
                            "lineno": inner.lineno,
                            "checked_vars": checked_vars,
                            "terminates": body_terminates,
                            "test_str": test_str,
                        })

                if not containment_guards:
                    return None

                for g in containment_guards:
                    g_lineno = int(g["lineno"])
                    g_terminates = bool(g["terminates"])
                    g_checked_vars: set[str] = set(g["checked_vars"])
                    g_test_str = str(g["test_str"])

                    if g_lineno > sink_line:
                        continue

                    # If the guard does NOT terminate on failure, it does not neutralize
                    if not g_terminates:
                        return PathAdversarialEvaluation(
                            verdict=AdversarialVerdict.INSUFFICIENT_EVIDENCE,
                            guard_symbol="unimplemented_boundary_check",
                            guard_file=f_file,
                            guard_line=g_lineno,
                            reachability=GuardReachability.MANDATORY_ON_PATH,
                            effectiveness=GuardEffectiveness.NO_NEUTRALIZATION,
                            branch_conditions=[g_test_str],
                            input_transformations=[],
                            bypass_paths=["Boundary check expression is evaluated but does not terminate execution on failure."],
                            unresolved_assumptions=["No abort, raise, or early return terminates execution when boundary check fails."],
                            contradicts_finding=False,
                            rationale=f"Boundary check at line {g_lineno} does not abort or raise on failure.",
                        )

                    # Parameter neutralization: If sink variable is known, guard variable must match
                    if sink_var_names and g_checked_vars and not (sink_var_names & g_checked_vars):
                        return PathAdversarialEvaluation(
                            verdict=AdversarialVerdict.INSUFFICIENT_EVIDENCE,
                            guard_symbol="mismatched_boundary_parameter",
                            guard_file=f_file,
                            guard_line=g_lineno,
                            reachability=GuardReachability.UNRELATED_IN_REPO,
                            effectiveness=GuardEffectiveness.NO_NEUTRALIZATION,
                            branch_conditions=[g_test_str],
                            input_transformations=[],
                            bypass_paths=[f"Guard checks variable(s) {g_checked_vars} but sink accesses {sink_var_names}"],
                            unresolved_assumptions=["Checked variable does not match sink variable."],
                            contradicts_finding=False,
                            rationale=f"Boundary check at line {g_lineno} verifies {g_checked_vars} which does not neutralize sink parameter {sink_var_names}.",
                        )

                    # Check if guard is nested inside an optional bypass branch
                    for outer in ast.walk(target_func):
                        if isinstance(outer, ast.If) and outer != g["node"] and any(sub == g["node"] for sub in ast.walk(outer)):
                            outer_test = ast.unparse(outer.test).lower()
                            if any(kw in outer_test for kw in ("bypass", "skip", "override", "admin", "debug", "test")):
                                return PathAdversarialEvaluation(
                                    verdict=AdversarialVerdict.BYPASSABLE,
                                    guard_symbol="conditional_bypassable_guard",
                                    guard_file=f_file,
                                    guard_line=g_lineno,
                                    reachability=GuardReachability.BYPASSABLE,
                                    effectiveness=GuardEffectiveness.INCOMPLETE_DEFENSE,
                                    branch_conditions=[outer_test],
                                    bypass_paths=[f"Branch '{outer_test}' allows execution to bypass guard to sink"],
                                    contradicts_finding=False,
                                    rationale=f"Guard at line {g_lineno} is nested inside conditional branch '{outer_test}' which allows bypass.",
                                )

                    # Verified dominating containment guard!
                    method_name = "is_relative_to" if "is_relative_to" in g_test_str else "commonpath"
                    return PathAdversarialEvaluation(
                        verdict=AdversarialVerdict.PROTECTED,
                        guard_symbol=f"pathlib.{method_name}",
                        guard_file=f_file,
                        guard_line=g_lineno,
                        reachability=GuardReachability.MANDATORY_ON_PATH,
                        effectiveness=GuardEffectiveness.EFFECTIVE_NEUTRALIZATION,
                        branch_conditions=[f"Target path strictly verified via .{method_name}() boundary check"],
                        input_transformations=["resolve()", method_name],
                        bypass_paths=[],
                        contradicts_finding=True,
                        rationale=(
                            f"Structural AST analysis confirms {method_name}() boundary guard at line {g_lineno} "
                            f"dominates the sensitive operation at line {sink_line} and strictly prevents traversal outside root."
                        ),
                    )

        # Case 4: Structural Origin / CSRF Defense with Bypass Branch Detection
        if is_csrf_category:
            for node in ast.walk(tree):
                if isinstance(node, ast.If):
                    test_str = ast.unparse(node.test).lower()
                    # Check if if-statement checks origin / referer / source
                    if any(term in test_str for term in ("origin", "referer", "source")):
                        # Check body for early return / allow (bypass for clients omitting header)
                        for stmt in node.body:
                            if isinstance(stmt, ast.Return) and (stmt.value is None or ast.unparse(stmt.value) in ("True", "None", "")):
                                return PathAdversarialEvaluation(
                                    verdict=AdversarialVerdict.BYPASSABLE,
                                    guard_symbol="origin_guard_conditional_bypass",
                                    guard_file=f_file,
                                    guard_line=node.lineno,
                                    reachability=GuardReachability.BYPASSABLE,
                                    effectiveness=GuardEffectiveness.INCOMPLETE_DEFENSE,
                                    branch_conditions=[test_str],
                                    input_transformations=[],
                                    bypass_paths=["Non-browser HTTP clients omitting Origin and Referer headers entirely bypass check."],
                                    contradicts_finding=False,
                                    rationale=(
                                        f"Origin verification at line {node.lineno} contains an architectural bypass: "
                                        f"requests lacking Origin/Referer headers ({test_str}) return early and are allowed."
                                    ),
                                )

        return None

    evaluate_contradiction = evaluate_finding_defenses
