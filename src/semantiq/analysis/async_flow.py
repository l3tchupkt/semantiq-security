"""Evidence-backed asynchronous boundary and security flow modeling.

Models message publication, task scheduling, queue boundaries, consumer handlers,
payload field propagation, worker authorization, tenant isolation, and concurrency/idempotency.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from semantiq.repository.safepath import resolve_safe_path


class AsyncResolutionMethod(str, Enum):
    """Resolution confidence and epistemological grounding for an async flow edge."""

    CONFIRMED_DIRECT = "confirmed_direct"  # Direct function or callable reference (1.0 confidence)
    FRAMEWORK_RESOLVED = "framework_resolved"  # Named queue, task name, or routing key matched via framework conventions (0.85-0.95 confidence)
    PROBABLE_UNVERIFIED = "probable_unverified"  # Heuristically matched queue structure and compatible payload schema (0.65-0.75 confidence)
    UNRESOLVED_DYNAMIC = "unresolved_dynamic"  # Dynamic dispatch or runtime-computed queue/task (0.20-0.40 confidence)


class AsyncFrameworkKind(str, Enum):
    """Underlying asynchronous task or messaging framework pattern."""

    CELERY = "celery"
    FASTAPI_BACKGROUND = "fastapi_background"
    REDIS_QUEUE = "redis_queue"
    IN_MEMORY_QUEUE = "in_memory_queue"
    CUSTOM_DISPATCHER = "custom_dispatcher"


@dataclass
class PayloadFieldPropagation:
    """Tracks how a specific payload field flows from message producer into worker sinks."""

    field_name: str
    producer_expression: str
    consumer_usage: str
    reaches_sensitive_sink: bool = False
    sink_category: str | None = None
    sink_file: str | None = None
    sink_line: int | None = None
    is_caller_controlled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_name": self.field_name,
            "producer_expression": self.producer_expression,
            "consumer_usage": self.consumer_usage,
            "reaches_sensitive_sink": self.reaches_sensitive_sink,
            "sink_category": self.sink_category,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "is_caller_controlled": self.is_caller_controlled,
        }


@dataclass
class AsyncSecurityBoundary:
    """Security invariants and authorization controls evaluated across the async boundary."""

    producer_authenticated: bool = False
    producer_auth_details: list[str] = field(default_factory=list)
    consumer_reauthorizes: bool = False
    consumer_auth_details: list[str] = field(default_factory=list)
    tenant_isolated: bool = True
    tenant_propagation_method: str = "none"  # "verified_context", "untrusted_payload", "none"
    has_idempotency_guard: bool = False
    idempotency_mechanism: str = "none"  # "atomic_lock", "database_transaction", "idempotency_token", "none"
    has_retry_risk: bool = False
    invariant_violations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "producer_authenticated": self.producer_authenticated,
            "producer_auth_details": list(self.producer_auth_details),
            "consumer_reauthorizes": self.consumer_reauthorizes,
            "consumer_auth_details": list(self.consumer_auth_details),
            "tenant_isolated": self.tenant_isolated,
            "tenant_propagation_method": self.tenant_propagation_method,
            "has_idempotency_guard": self.has_idempotency_guard,
            "idempotency_mechanism": self.idempotency_mechanism,
            "has_retry_risk": self.has_retry_risk,
            "invariant_violations": list(self.invariant_violations),
        }


@dataclass
class AsyncProducerFact:
    """Observed code fact: task scheduling, message enqueue, or event publication."""

    producer_id: str
    file_path: str
    symbol_name: str
    line: int
    framework: AsyncFrameworkKind
    queue_name: str
    task_name: str | None = None
    target_callable: str | None = None
    payload_fields: list[str] = field(default_factory=list)
    payload_expressions: dict[str, str] = field(default_factory=dict)
    is_dynamic: bool = False
    authenticated: bool = False
    auth_decorators: list[str] = field(default_factory=list)
    code_snippet: str = ""
    has_pre_dispatch_lock: bool = False
    lock_mechanism: str = ""


@dataclass
class AsyncConsumerFact:
    """Observed code fact: worker entry point, background handler, or queue subscriber."""

    consumer_id: str
    file_path: str
    symbol_name: str
    line: int
    framework: AsyncFrameworkKind
    queue_name: str | None = None
    task_name: str | None = None
    consumed_fields: list[str] = field(default_factory=list)
    reauthorizes: bool = False
    auth_decorators: list[str] = field(default_factory=list)
    code_snippet: str = ""
    sensitive_sinks_reached: list[dict[str, Any]] = field(default_factory=list)
    has_idempotency_guard: bool = False
    idempotency_mechanism: str = ""
    is_tenant_filtered: bool = False


@dataclass
class AsyncFlowEdge:
    """A typed, evidence-backed edge connecting an asynchronous producer to a consumer."""

    flow_id: str
    framework: AsyncFrameworkKind
    resolution_method: AsyncResolutionMethod
    confidence: float
    producer_file: str
    producer_symbol: str
    producer_line: int
    queue_name: str
    task_name: str | None = None
    payload_schema: list[str] = field(default_factory=list)
    consumer_file: str | None = None
    consumer_symbol: str | None = None
    consumer_line: int | None = None
    payload_propagations: list[PayloadFieldPropagation] = field(default_factory=list)
    security_boundary: AsyncSecurityBoundary = field(default_factory=AsyncSecurityBoundary)
    evidence: list[str] = field(default_factory=list)
    unresolved_assumptions: list[str] = field(default_factory=list)
    reason_unresolved: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "framework": self.framework.value,
            "resolution_method": self.resolution_method.value,
            "confidence": self.confidence,
            "producer_file": self.producer_file,
            "producer_symbol": self.producer_symbol,
            "producer_line": self.producer_line,
            "queue_name": self.queue_name,
            "task_name": self.task_name,
            "payload_schema": list(self.payload_schema),
            "consumer_file": self.consumer_file,
            "consumer_symbol": self.consumer_symbol,
            "consumer_line": self.consumer_line,
            "payload_propagations": [p.to_dict() for p in self.payload_propagations],
            "security_boundary": self.security_boundary.to_dict(),
            "evidence": list(self.evidence),
            "unresolved_assumptions": list(self.unresolved_assumptions),
            "reason_unresolved": self.reason_unresolved,
        }


class AsyncFlowAnalyzer:
    """Discovers, links, and evaluates security invariants across asynchronous boundaries."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.producers: list[AsyncProducerFact] = []
        self.consumers: list[AsyncConsumerFact] = []
        self.flows: list[AsyncFlowEdge] = []

    def analyze_repository(self, in_scope_files: list[str]) -> list[AsyncFlowEdge]:
        """Index all producers and consumers across files, then resolve evidence-backed edges."""
        self.producers.clear()
        self.consumers.clear()
        self.flows.clear()

        # Step 1: Parse files and extract producer and consumer facts
        for rel_path in in_scope_files:
            clean_rel = rel_path.replace("\\", "/")
            if not clean_rel.endswith((".py", ".pyi")):
                continue
            try:
                full_p = resolve_safe_path(self.repo_root, clean_rel)
                if not full_p.is_file():
                    continue
                code = full_p.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(code, filename=clean_rel)
                self._extract_file_async_facts(tree, clean_rel, code)
            except Exception:
                continue

        # Step 2: Correlate producers to consumers with strict evidence rules
        self._correlate_flows()
        return list(self.flows)

    def _extract_file_async_facts(self, tree: ast.AST, rel_path: str, code: str) -> None:
        """Scan AST for queue publishers, task schedulers, and consumer handlers."""
        lines = code.splitlines()

        # Identify declared queue identifiers in this file (e.g. PENDING_QUEUE = [], EXECUTION_QUEUE = [])
        declared_queues: set[str] = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    t_name = getattr(target, "id", "")
                    if any(k in t_name.upper() for k in ("QUEUE", "CHANNEL", "TOPIC", "BROKER")):
                        declared_queues.add(t_name)

        class FactVisitor(ast.NodeVisitor):
            def __init__(self, outer: AsyncFlowAnalyzer) -> None:
                self.outer = outer
                self.curr_func: str = "<module>"
                self.curr_func_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
                self.curr_decorators: list[str] = []

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._handle_function_entry(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._handle_function_entry(node)

            def _handle_function_entry(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                prev_func = self.curr_func
                prev_node = self.curr_func_node
                prev_decs = self.curr_decorators

                self.curr_func = node.name
                self.curr_func_node = node
                self.curr_decorators = [self.outer._format_decorator(d) for d in node.decorator_list]

                # Check if this function is a consumer/worker
                self._inspect_consumer_candidate(node, rel_path, lines)

                self.generic_visit(node)

                self.curr_func = prev_func
                self.curr_func_node = prev_node
                self.curr_decorators = prev_decs

            def _inspect_consumer_candidate(
                self,
                node: ast.FunctionDef | ast.AsyncFunctionDef,
                file_path: str,
                file_lines: list[str],
            ) -> None:
                is_consumer = False
                framework = AsyncFrameworkKind.CUSTOM_DISPATCHER
                task_name: str | None = None
                queue_name: str | None = None

                # 1. Celery task decorator: @app.task, @celery.task, @shared_task
                for dec in self.curr_decorators:
                    if any(c in dec for c in ("task", "shared_task")):
                        is_consumer = True
                        framework = AsyncFrameworkKind.CELERY
                        # Extract explicit task name or default to function name
                        for d_ast in node.decorator_list:
                            if isinstance(d_ast, ast.Call):
                                for kw in d_ast.keywords:
                                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                                        task_name = str(kw.value.value)
                                    elif kw.arg == "queue" and isinstance(kw.value, ast.Constant):
                                        queue_name = str(kw.value.value)
                        if not task_name:
                            task_name = node.name

                # 2. Worker function name or parameter heuristics
                lower_name = node.name.lower()
                param_names = [arg.arg for arg in node.args.args]
                is_worker_signature = any(p in param_names for p in ("job", "task", "message", "payload"))
                is_worker_name = any(k in lower_name for k in ("worker", "consumer", "process_", "handle_job", "on_message"))

                # Dispatchers and producers are NOT consumers
                if lower_name.startswith("dispatch_") or lower_name.startswith("send_") or lower_name.startswith("publish_"):
                    is_consumer = False
                elif not is_consumer and (is_worker_signature or is_worker_name):
                    # Check if file or function accesses queues
                    func_code = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    if is_worker_signature or any(q in func_code for q in declared_queues) or "workers" in file_path:
                        is_consumer = True
                        framework = AsyncFrameworkKind.IN_MEMORY_QUEUE

                if is_consumer:
                    # Extract fields consumed from job/task dictionary
                    consumed_fields: list[str] = []
                    sinks_reached: list[dict[str, Any]] = []
                    has_idempotency_guard = False
                    idempotency_mechanism = "none"
                    is_tenant_filtered = False

                    # Walk function body to detect field subscripting and sink invocations
                    for child in ast.walk(node):
                        # Detect job["field_name"]
                        if (
                            isinstance(child, ast.Subscript)
                            and isinstance(child.value, ast.Name)
                            and child.value.id in ("job", "task", "payload", "message", "bundle")
                            and isinstance(child.slice, ast.Constant)
                            and isinstance(child.slice.value, str)
                        ):
                            consumed_fields.append(child.slice.value)

                        # Detect job.get("field_name")
                        elif (
                            isinstance(child, ast.Call)
                            and isinstance(child.func, ast.Attribute)
                            and child.func.attr == "get"
                            and isinstance(child.func.value, ast.Name)
                            and child.func.value.id in ("job", "task", "payload", "message", "bundle")
                            and child.args
                            and isinstance(child.args[0], ast.Constant)
                            and isinstance(child.args[0].value, str)
                        ):
                            consumed_fields.append(child.args[0].value)

                        # Detect sensitive sink invocations inside worker
                        if isinstance(child, ast.Call):
                            call_name = getattr(child.func, "id", "") or getattr(child.func, "attr", "")
                            if any(k in call_name.lower() for k in ("execute", "refund", "delete", "destroy", "purge", "subprocess", "system", "load_tenant", "record_ledger")):
                                call_args_text = ast.unparse(child) if hasattr(ast, "unparse") else ""
                                sinks_reached.append({
                                    "sink_symbol": call_name,
                                    "line": getattr(child, "lineno", node.lineno),
                                    "sink_category": "privileged_operation",
                                    "args_text": call_args_text,
                                })

                            # Detect idempotency / transaction guards
                            if any(k in call_name.lower() for k in ("lock", "atomic", "idempotent", "transaction", "select_for_update", "status_check", "verify_")):
                                has_idempotency_guard = True
                                idempotency_mechanism = call_name

                    # Check for tenant ownership filtering
                    func_text = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    if any(k in func_text for k in ("verify_tenant", "check_tenant", "tenant_id = current_tenant", "org_id ==")):
                        is_tenant_filtered = True

                    # Check for worker-side authorization checks
                    reauthorizes = False
                    auth_decs = [d for d in self.curr_decorators if any(k in d.lower() for k in ("auth", "admin", "permission", "jwt"))]
                    if auth_decs or any(k in func_text for k in ("is_admin", "check_permission", "verify_signature", "auth_service", "verify_")):
                        reauthorizes = True

                    snippet = file_lines[node.lineno - 1].strip() if 0 < node.lineno <= len(file_lines) else ""
                    self.outer.consumers.append(
                        AsyncConsumerFact(
                            consumer_id=f"consumer:{file_path}:{node.name}:{node.lineno}",
                            file_path=file_path,
                            symbol_name=node.name,
                            line=node.lineno,
                            framework=framework,
                            queue_name=queue_name,
                            task_name=task_name,
                            consumed_fields=sorted(set(consumed_fields)),
                            reauthorizes=reauthorizes,
                            auth_decorators=auth_decs,
                            code_snippet=snippet,
                            sensitive_sinks_reached=sinks_reached,
                            has_idempotency_guard=has_idempotency_guard,
                            idempotency_mechanism=idempotency_mechanism,
                            is_tenant_filtered=is_tenant_filtered,
                        )
                    )

            def visit_Call(self, node: ast.Call) -> None:
                # Detect async producers (enqueue, delay, apply_async, send_task, add_task, queue.append)
                call_name = ""
                caller_attr = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                    caller_attr = getattr(node.func.value, "id", "") or getattr(node.func.value, "attr", "")

                is_producer = False
                framework = AsyncFrameworkKind.CUSTOM_DISPATCHER
                queue_name = ""
                task_name: str | None = None
                target_callable: str | None = None
                is_dynamic = False
                payload_fields: list[str] = []
                payload_expressions: dict[str, str] = {}

                # Pattern A: Celery delay() or apply_async()
                if call_name in ("delay", "apply_async") and caller_attr:
                    is_producer = True
                    framework = AsyncFrameworkKind.CELERY
                    target_callable = caller_attr
                    task_name = caller_attr
                    # Extract keyword arguments passed to task
                    for kw in node.keywords:
                        if kw.arg:
                            payload_fields.append(kw.arg)
                            payload_expressions[kw.arg] = ast.unparse(kw.value) if hasattr(ast, "unparse") else kw.arg

                # Pattern B: Celery send_task("task_name", ...)
                elif call_name == "send_task":
                    is_producer = True
                    framework = AsyncFrameworkKind.CELERY
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        task_name = node.args[0].value
                    else:
                        is_dynamic = True
                        task_name = "<dynamic_task>"

                # Pattern C: FastAPI BackgroundTasks.add_task(func, *args, **kwargs)
                elif call_name == "add_task":
                    is_producer = True
                    framework = AsyncFrameworkKind.FASTAPI_BACKGROUND
                    if node.args:
                        target_callable = getattr(node.args[0], "id", "") or getattr(node.args[0], "attr", "")
                        for kw in node.keywords:
                            if kw.arg:
                                payload_fields.append(kw.arg)
                    else:
                        is_dynamic = True

                # Pattern D: Redis queue: rpush(queue_name, payload) or lpush
                elif call_name in ("rpush", "lpush"):
                    is_producer = True
                    framework = AsyncFrameworkKind.REDIS_QUEUE
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        queue_name = node.args[0].value
                    else:
                        is_dynamic = True
                        queue_name = "<dynamic_redis_queue>"

                # Pattern E: Custom or in-memory queue dispatch (append to QUEUE, dispatch_*_job)
                elif call_name == "append" and (caller_attr in declared_queues or any(q in caller_attr.upper() for q in ("QUEUE", "JOBS", "TASKS"))):
                    is_producer = True
                    framework = AsyncFrameworkKind.IN_MEMORY_QUEUE
                    queue_name = caller_attr

                    # Detect dynamic queue variable (e.g. parameter passed into function)
                    func_param_names = [arg.arg for arg in self.curr_func_node.args.args] if self.curr_func_node else []
                    if caller_attr in func_param_names or (caller_attr not in declared_queues and not caller_attr.isupper()):
                        is_dynamic = True
                        task_name = "<dynamic_task>"

                    # Extract payload fields from dictionary argument
                    if node.args and isinstance(node.args[0], ast.Dict):
                        for k, v in zip(node.args[0].keys, node.args[0].values, strict=False):
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                payload_fields.append(k.value)
                                payload_expressions[k.value] = ast.unparse(v) if hasattr(ast, "unparse") else str(k.value)
                    elif node.args and isinstance(node.args[0], ast.Name):
                        # Passed variable: attempt to find prior assignment in function
                        var_name = node.args[0].id
                        payload_fields, payload_expressions = self.outer._resolve_local_dict_fields(self.curr_func_node, var_name)

                # Pattern F: Explicit dispatch function call: dispatch_refund_job, dispatch_workload_execution
                elif call_name.startswith("dispatch_") or "enqueue" in call_name.lower():
                    is_producer = True
                    framework = AsyncFrameworkKind.CUSTOM_DISPATCHER
                    queue_name = call_name
                    # Check if any argument is dynamically resolved
                    if any("dynamic" in getattr(a, "id", "").lower() for a in node.args if isinstance(a, ast.Name)):
                        is_dynamic = True
                    for kw in node.keywords:
                        if kw.arg:
                            payload_fields.append(kw.arg)
                            payload_expressions[kw.arg] = ast.unparse(kw.value) if hasattr(ast, "unparse") else kw.arg

                if is_producer:
                    # Check enclosing function authentication & lock
                    auth_decs = [d for d in self.curr_decorators if any(k in d.lower() for k in ("jwt", "auth", "login", "admin"))]
                    is_auth = len(auth_decs) > 0

                    func_text = ast.unparse(self.curr_func_node) if (self.curr_func_node and hasattr(ast, "unparse")) else ""
                    has_pre_lock = any(k in func_text for k in ("lock", "atomic", "claim_atomic", "reservation"))
                    lock_mech = "atomic_lock" if has_pre_lock else "none"

                    lineno = getattr(node, "lineno", 1)
                    snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                    self.outer.producers.append(
                        AsyncProducerFact(
                            producer_id=f"producer:{rel_path}:{self.curr_func}:{lineno}",
                            file_path=rel_path,
                            symbol_name=self.curr_func,
                            line=lineno,
                            framework=framework,
                            queue_name=queue_name,
                            task_name=task_name,
                            target_callable=target_callable,
                            payload_fields=sorted(set(payload_fields)),
                            payload_expressions=payload_expressions,
                            is_dynamic=is_dynamic,
                            authenticated=is_auth,
                            auth_decorators=auth_decs,
                            code_snippet=snippet,
                            has_pre_dispatch_lock=has_pre_lock,
                            lock_mechanism=lock_mech,
                        )
                    )

                self.generic_visit(node)

        visitor = FactVisitor(self)
        visitor.visit(tree)

    def _resolve_local_dict_fields(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
        var_name: str,
    ) -> tuple[list[str], dict[str, str]]:
        """Look back within the function body to extract keys from dict assignment."""
        fields: list[str] = []
        exprs: dict[str, str] = {}
        if not func_node:
            return fields, exprs

        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if getattr(target, "id", "") == var_name and isinstance(node.value, ast.Dict):
                        for k, v in zip(node.value.keys, node.value.values, strict=False):
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                fields.append(k.value)
                                exprs[k.value] = ast.unparse(v) if hasattr(ast, "unparse") else str(k.value)
        return fields, exprs

    def _format_decorator(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._format_decorator(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._format_decorator(node.func)
        return ""

    def _correlate_flows(self) -> None:
        """Resolve evidence-backed async flow edges connecting producers to consumers."""
        flow_idx = 0

        # Step A: Link caller dispatch invocations (e.g. API layer) to broker queue enqueue definitions
        # If there is a broker producer whose symbol_name is F (e.g. dispatch_tenant_export in task_broker.py)
        # and another producer whose queue_name is F (e.g. submit_tenant_export calling dispatch_tenant_export in api/tasks.py):
        broker_producers_by_func: dict[str, AsyncProducerFact] = {
            p.symbol_name: p
            for p in self.producers
            if p.symbol_name.startswith("dispatch_") or "enqueue" in p.symbol_name.lower()
        }

        filtered_producers: list[AsyncProducerFact] = []
        for p in self.producers:
            # If this producer is an invocation of a broker function that is also present as a producer
            if p.queue_name in broker_producers_by_func:
                broker_p = broker_producers_by_func[p.queue_name]
                # Propagate caller auth, lock, and expression metadata into broker producer
                if p.authenticated:
                    broker_p.authenticated = True
                    broker_p.auth_decorators = list(set(broker_p.auth_decorators + p.auth_decorators))
                if p.has_pre_dispatch_lock:
                    broker_p.has_pre_dispatch_lock = True
                    broker_p.lock_mechanism = p.lock_mechanism
                broker_p.payload_expressions.update(p.payload_expressions)
                if p.is_dynamic:
                    broker_p.is_dynamic = True
                # Skip the caller producer so we don't produce duplicate flows
                continue
            filtered_producers.append(p)

        for prod in filtered_producers:
            flow_idx += 1
            flow_id = f"async_flow_{flow_idx:03d}"

            # Case 1: Dynamic dispatch without static resolvable target
            if prod.is_dynamic:
                self.flows.append(
                    AsyncFlowEdge(
                        flow_id=flow_id,
                        framework=prod.framework,
                        resolution_method=AsyncResolutionMethod.UNRESOLVED_DYNAMIC,
                        confidence=0.30,
                        producer_file=prod.file_path,
                        producer_symbol=prod.symbol_name,
                        producer_line=prod.line,
                        queue_name=prod.queue_name,
                        task_name=prod.task_name,
                        payload_schema=prod.payload_fields,
                        consumer_file=None,
                        consumer_symbol=None,
                        consumer_line=None,
                        security_boundary=AsyncSecurityBoundary(
                            producer_authenticated=prod.authenticated,
                            producer_auth_details=prod.auth_decorators,
                        ),
                        evidence=[f"Dynamic dispatch: queue or task target is computed at runtime from variable in {prod.file_path}:{prod.line}"],
                        unresolved_assumptions=["Target worker cannot be statically determined without runtime configuration"],
                        reason_unresolved="Dynamic dispatch: runtime-computed queue or task prevents static resolution of consumer target",
                    )
                )
                continue

            # Case 2: Direct callable reference (e.g. background_tasks.add_task(worker_fn) or task.delay())
            direct_match: AsyncConsumerFact | None = None
            if prod.target_callable:
                for cons in self.consumers:
                    if cons.symbol_name == prod.target_callable:
                        direct_match = cons
                        break

            if direct_match:
                self._create_edge(
                    flow_id=flow_id,
                    prod=prod,
                    cons=direct_match,
                    method=AsyncResolutionMethod.CONFIRMED_DIRECT,
                    confidence=1.0,
                    evidence=[f"Direct callable reference '{prod.target_callable}' resolved between producer and worker"],
                )
                continue

            # Case 3: Framework-resolved task name (e.g. Celery send_task("task_name") <-> @app.task(name="task_name"))
            if prod.task_name and prod.task_name != "<dynamic_task>":
                task_matches = [c for c in self.consumers if c.task_name == prod.task_name]
                if len(task_matches) == 1:
                    self._create_edge(
                        flow_id=flow_id,
                        prod=prod,
                        cons=task_matches[0],
                        method=AsyncResolutionMethod.FRAMEWORK_RESOLVED,
                        confidence=0.95,
                        evidence=[f"Explicit task name '{prod.task_name}' matched to registered worker entry point"],
                    )
                    continue

            # Case 4: Queue / Channel / Dispatcher name match with compatible payload schema
            # Negative Case Guard: Ensure we do NOT link disjoint queues (e.g. analytics vs refunds)
            candidate_consumers: list[tuple[AsyncConsumerFact, float, list[str]]] = []
            for cons in self.consumers:
                # Check for queue name match
                queue_match = bool(
                    (prod.queue_name and cons.queue_name and prod.queue_name == cons.queue_name)
                    or (
                        prod.queue_name
                        and any(
                            term in cons.file_path.lower() or term in cons.symbol_name.lower()
                            for term in prod.queue_name.lower().split("_")
                            if len(term) > 3
                        )
                    )
                )

                # Check for payload field compatibility
                prod_fields = set(prod.payload_fields)
                cons_fields = set(cons.consumed_fields)
                shared_fields = prod_fields.intersection(cons_fields)

                # Negative Case Protection: Disjoint fields or differing queue systems must NOT connect
                if prod.framework != cons.framework and prod.framework not in (AsyncFrameworkKind.IN_MEMORY_QUEUE, AsyncFrameworkKind.CUSTOM_DISPATCHER):
                    continue

                if queue_match and (shared_fields or not cons_fields):
                    evidence_notes = [
                        f"Queue/channel '{prod.queue_name}' matched between {prod.file_path} and {cons.file_path}",
                    ]
                    if shared_fields:
                        evidence_notes.append(f"Payload fields correlated: {sorted(shared_fields)}")
                    conf = 0.85 if shared_fields else 0.70
                    candidate_consumers.append((cons, conf, evidence_notes))
                elif not queue_match and shared_fields and len(shared_fields) >= 1:
                    # Probable unverified connection (same schema across boundary without explicit queue name)
                    evidence_notes = [
                        f"Matching payload schema across boundary ({sorted(shared_fields)}), but queue name not explicitly shared",
                    ]
                    candidate_consumers.append((cons, 0.65, evidence_notes))

            if len(candidate_consumers) == 1:
                cons, conf, ev = candidate_consumers[0]
                method = AsyncResolutionMethod.FRAMEWORK_RESOLVED if conf >= 0.80 else AsyncResolutionMethod.PROBABLE_UNVERIFIED
                self._create_edge(
                    flow_id=flow_id,
                    prod=prod,
                    cons=cons,
                    method=method,
                    confidence=conf,
                    evidence=ev,
                )
            elif len(candidate_consumers) > 1:
                # Ambiguous: Link with lower confidence and explicit assumption
                best_cons, conf, ev = candidate_consumers[0]
                self._create_edge(
                    flow_id=flow_id,
                    prod=prod,
                    cons=best_cons,
                    method=AsyncResolutionMethod.PROBABLE_UNVERIFIED,
                    confidence=0.55,
                    evidence=ev + [f"Multiple candidate workers ({len(candidate_consumers)}) matched queue {prod.queue_name}; selection is ambiguous"],
                    unresolved_assumptions=["Multiple worker candidates exist; routing may depend on runtime configuration or load balancing"],
                )
            else:
                # Unresolved queue producer (no matching consumer found)
                self.flows.append(
                    AsyncFlowEdge(
                        flow_id=flow_id,
                        framework=prod.framework,
                        resolution_method=AsyncResolutionMethod.PROBABLE_UNVERIFIED,
                        confidence=0.40,
                        producer_file=prod.file_path,
                        producer_symbol=prod.symbol_name,
                        producer_line=prod.line,
                        queue_name=prod.queue_name,
                        task_name=prod.task_name,
                        payload_schema=prod.payload_fields,
                        consumer_file=None,
                        consumer_symbol=None,
                        consumer_line=None,
                        security_boundary=AsyncSecurityBoundary(
                            producer_authenticated=prod.authenticated,
                            producer_auth_details=prod.auth_decorators,
                        ),
                        evidence=[f"Producer publishes to queue '{prod.queue_name}' with fields {prod.payload_fields}"],
                        unresolved_assumptions=["No consumer worker found in in-scope files; worker may be an external service or daemon"],
                        reason_unresolved=f"No matching consumer found for queue '{prod.queue_name}'",
                    )
                )

        # Invariant and flow deduplication by unique edge signature
        seen_keys: set[tuple[str, str, str | None, str | None]] = set()
        deduped_flows: list[AsyncFlowEdge] = []
        for edge in self.flows:
            k = (edge.producer_file, edge.queue_name, edge.consumer_file, edge.consumer_symbol)
            if k not in seen_keys:
                seen_keys.add(k)
                deduped_flows.append(edge)
        self.flows = deduped_flows

    def _create_edge(
        self,
        flow_id: str,
        prod: AsyncProducerFact,
        cons: AsyncConsumerFact,
        method: AsyncResolutionMethod,
        confidence: float,
        evidence: list[str],
        unresolved_assumptions: list[str] | None = None,
    ) -> None:
        """Evaluate security boundaries, field propagation, and create the edge."""
        assumptions = list(unresolved_assumptions or [])

        # 1. Evaluate Field Propagations
        propagations: list[PayloadFieldPropagation] = []
        all_fields = sorted(set(prod.payload_fields).union(cons.consumed_fields))

        for fld in all_fields:
            prod_expr = prod.payload_expressions.get(fld, fld)
            cons_usage = f"job['{fld}']" if fld in cons.consumed_fields else f"payload.{fld}"

            # Check if this field reaches any sensitive sink in the consumer
            reaches_sink = False
            sink_cat: str | None = None
            sink_f: str | None = None
            sink_l: int | None = None

            if cons.sensitive_sinks_reached and any(
                p in fld.lower()
                for p in ("tenant", "user", "order", "recipient", "amount", "spec", "bundle")
            ):
                reaches_sink = True
                sink_info = cons.sensitive_sinks_reached[0]
                sink_cat = sink_info.get("sink_category", "privileged_operation")
                sink_f = cons.file_path
                sink_l = sink_info.get("line", cons.line)

            propagations.append(
                PayloadFieldPropagation(
                    field_name=fld,
                    producer_expression=prod_expr,
                    consumer_usage=cons_usage,
                    reaches_sensitive_sink=reaches_sink,
                    sink_category=sink_cat,
                    sink_file=sink_f,
                    sink_line=sink_l,
                    is_caller_controlled=(fld in prod.payload_fields),
                )
            )

        # 2. Evaluate Security Boundaries & Invariant Violations
        violations: list[str] = []

        # Check worker-side authorization
        consumer_reauth = cons.reauthorizes
        is_privileged_task = (
            any(
                k in (cons.symbol_name + prod.symbol_name + prod.queue_name).lower()
                for k in ("admin", "purge", "destroy", "superuser", "privilege", "delete_all")
            )
            or any(
                k in s.get("sink_symbol", "").lower()
                for s in cons.sensitive_sinks_reached
                for k in ("purge", "destroy", "delete_all", "drop")
            )
        )
        if not consumer_reauth and (is_privileged_task or not prod.authenticated) and cons.sensitive_sinks_reached:
            violations.append(
                "Missing worker-side authorization: background worker executes privileged operation without verifying caller authority"
            )

        # Check tenant isolation
        has_tenant_field = any("tenant" in f.lower() or "org" in f.lower() or "workspace" in f.lower() for f in all_fields)
        tenant_isolated = True
        tenant_prop = "none"

        if has_tenant_field:
            if cons.is_tenant_filtered:
                tenant_isolated = True
                tenant_prop = "verified_context"
            else:
                tenant_isolated = False
                tenant_prop = "untrusted_payload"
                violations.append(
                    "Cross-tenant execution risk: unverified tenant identifier in message payload directly influences worker execution scope"
                )

        # Check idempotency & concurrency
        has_idempotency = prod.has_pre_dispatch_lock or cons.has_idempotency_guard
        idempotency_mech = prod.lock_mechanism if prod.has_pre_dispatch_lock else (cons.idempotency_mechanism if cons.has_idempotency_guard else "none")
        has_retry_risk = False

        if not has_idempotency and any(k in cons.symbol_name.lower() or k in prod.symbol_name.lower() for k in ("refund", "payment", "payout", "order", "charge", "transfer")):
            has_retry_risk = True
            violations.append(
                "Non-idempotent operation: duplicate message delivery or retry executes external side effects without reservation locking"
            )

        sec_boundary = AsyncSecurityBoundary(
            producer_authenticated=prod.authenticated,
            producer_auth_details=prod.auth_decorators,
            consumer_reauthorizes=consumer_reauth,
            consumer_auth_details=cons.auth_decorators,
            tenant_isolated=tenant_isolated,
            tenant_propagation_method=tenant_prop,
            has_idempotency_guard=has_idempotency,
            idempotency_mechanism=idempotency_mech,
            has_retry_risk=has_retry_risk,
            invariant_violations=violations,
        )

        edge = AsyncFlowEdge(
            flow_id=flow_id,
            framework=prod.framework,
            resolution_method=method,
            confidence=confidence,
            producer_file=prod.file_path,
            producer_symbol=prod.symbol_name,
            producer_line=prod.line,
            queue_name=prod.queue_name,
            task_name=prod.task_name,
            payload_schema=all_fields,
            consumer_file=cons.file_path,
            consumer_symbol=cons.symbol_name,
            consumer_line=cons.line,
            payload_propagations=propagations,
            security_boundary=sec_boundary,
            evidence=evidence,
            unresolved_assumptions=assumptions,
            reason_unresolved=None,
        )
        self.flows.append(edge)
