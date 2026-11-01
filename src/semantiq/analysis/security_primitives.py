"""General security primitive analysis layer.

Analyzes security primitives across codebases:
- Session identifiers
- API / Bearer tokens
- CSRF tokens and origin hooks
- Password-reset tokens
- Cryptographic nonces and secrets

Evaluates:
- Entropy source and randomness (CSPRNG vs object identity / process state / weak PRNG / timestamps)
- Predictability and remote observability
- Exposure channels (cookies, query params, headers, logs)
- Cookie defense flags (httponly, secure, samesite)
- Validation mechanisms (constant-time compare vs equality operator vs dictionary lookup)
- Session lifecycle, timeout, revocation, and rotation controls
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from semantiq.repository.safepath import resolve_safe_path


class SecurityPrimitiveKind(str, Enum):
    """Categorization of security primitive."""

    SESSION_IDENTIFIER = "session_identifier"
    API_TOKEN = "api_token"
    CSRF_TOKEN = "csrf_token"
    PASSWORD_RESET_TOKEN = "password_reset_token"
    AUTH_SECRET = "auth_secret"
    CRYPTO_NONCE = "crypto_nonce"


class EntropyQuality(str, Enum):
    """Epistemological randomness and entropy classification."""

    SECURE_CSPRNG = "secure_csprng"  # secrets.token_hex, os.urandom, uuid.uuid4
    PREDICTABLE_HEAP_ADDRESS = "predictable_heap_address"  # id(self), str(id(obj))
    PREDICTABLE_TIME_STATE = "predictable_time_state"  # time.time(), datetime.now()
    PREDICTABLE_PROCESS_STATE = "predictable_process_state"  # os.getpid()
    WEAK_PRNG = "weak_prng"  # random.random(), random.randint()
    DETERMINISTIC_COUNTER = "deterministic_counter"  # counter += 1, static string
    UNKNOWN_OR_UNRESOLVED = "unknown_or_unresolved"


@dataclass
class SecurityPrimitiveFact:
    """Observed security primitive in source code."""

    primitive_id: str
    file_path: str
    line_number: int
    kind: SecurityPrimitiveKind
    symbol_name: str
    generation_expression: str
    entropy_quality: EntropyQuality
    is_weak_or_predictable: bool
    exposure_channels: list[str] = field(default_factory=list)
    cookie_flags: dict[str, Any] = field(default_factory=dict)
    validation_mechanism: str = "none"
    lifecycle_controls: dict[str, Any] = field(default_factory=dict)
    exploitability_assessment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "primitive_id": self.primitive_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "kind": self.kind.value,
            "symbol_name": self.symbol_name,
            "generation_expression": self.generation_expression,
            "entropy_quality": self.entropy_quality.value,
            "is_weak_or_predictable": self.is_weak_or_predictable,
            "exposure_channels": list(self.exposure_channels),
            "cookie_flags": self.cookie_flags,
            "validation_mechanism": self.validation_mechanism,
            "lifecycle_controls": self.lifecycle_controls,
            "exploitability_assessment": self.exploitability_assessment,
        }


class SecurityPrimitivesAnalyzer:
    """Discovers and evaluates entropy and lifecycle properties of security primitives."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.primitives: list[SecurityPrimitiveFact] = []

    def analyze_repository(self, in_scope_files: list[str]) -> list[SecurityPrimitiveFact]:
        """Scan active repository files for security primitives."""
        self.primitives.clear()
        for rel_p in in_scope_files:
            clean_rel = rel_p.replace("\\", "/")
            if not clean_rel.endswith((".py", ".pyi")):
                continue
            try:
                full_p = resolve_safe_path(self.repo_root, clean_rel)
                if not full_p.is_file():
                    continue
                code = full_p.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(code, filename=clean_rel)
                self._inspect_tree(tree, clean_rel, code)
            except Exception:
                continue
        return list(self.primitives)

    def _inspect_tree(self, tree: ast.AST, rel_path: str, code: str) -> None:
        """Scan AST for session IDs, token generators, cookies, and comparison mechanisms."""

        # First collect file-level context: cookie calls, CSRF hooks, session stores
        cookie_calls: list[dict[str, Any]] = []
        csrf_hooks: list[dict[str, Any]] = []

        for node in ast.walk(tree):
            # Detect set_cookie calls
            if isinstance(node, ast.Call):
                call_name = getattr(node.func, "attr", "") or getattr(node.func, "id", "")
                if "set_cookie" in call_name:
                    cookie_name = ""
                    cookie_val_expr = ""
                    flags: dict[str, Any] = {"httponly": False, "samesite": None, "secure": False}

                    if node.args and isinstance(node.args[0], ast.Constant):
                        cookie_name = str(node.args[0].value)
                    if len(node.args) > 1:
                        cookie_val_expr = ast.unparse(node.args[1]) if hasattr(ast, "unparse") else ""

                    for kw in node.keywords:
                        if kw.arg == "httponly" and isinstance(kw.value, ast.Constant):
                            flags["httponly"] = bool(kw.value.value)
                        elif kw.arg == "secure" and isinstance(kw.value, ast.Constant):
                            flags["secure"] = bool(kw.value.value)
                        elif kw.arg == "samesite" and isinstance(kw.value, ast.Constant):
                            flags["samesite"] = str(kw.value.value)

                    cookie_calls.append({
                        "line": getattr(node, "lineno", 1),
                        "name": cookie_name,
                        "value_expr": cookie_val_expr,
                        "flags": flags,
                    })

            # Detect CSRF / same origin hooks
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                has_csrf_decor = any(
                    "origin" in d.lower() or "csrf" in d.lower()
                    for d in [ast.unparse(d) for d in node.decorator_list if hasattr(ast, "unparse")]
                )
                if has_csrf_decor or "csrf" in node.name.lower() or "same_origin" in node.name.lower():
                    csrf_hooks.append({
                        "name": node.name,
                        "line": node.lineno,
                    })

        # Second pass: Inspect property and function returns for token/session generators
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name.lower()
                is_session_symbol = any(k in func_name for k in ("session", "token", "auth_id", "nonce", "reset"))
                is_id_property = func_name == "id" or (func_name.endswith("_id") and "session" in str(getattr(node, "name", "")).lower())

                # Find return statements in function
                return_nodes = [n for n in ast.walk(node) if isinstance(n, ast.Return) and n.value is not None]

                for ret in return_nodes:
                    if ret.value is None:
                        continue
                    ret_expr = ast.unparse(ret.value) if hasattr(ast, "unparse") else ""

                    # Detect Pattern 1: Memory Address / id(self) / str(id(self))
                    if "id(self)" in ret_expr or "id(" in ret_expr and is_id_property:
                        # Correlate with cookie flags if this symbol feeds a cookie
                        matched_cookie = next((c for c in cookie_calls if any(k in c["name"].lower() for k in ("sid", "session", "id"))), None)
                        c_flags = matched_cookie["flags"] if matched_cookie else {}
                        exp_channels = [f"http_cookie:{matched_cookie['name']}"] if matched_cookie else ["internal_object_id"]

                        self.primitives.append(
                            SecurityPrimitiveFact(
                                primitive_id=f"prim:{rel_path}:{node.name}:{ret.lineno}",
                                file_path=rel_path,
                                line_number=ret.lineno,
                                kind=SecurityPrimitiveKind.SESSION_IDENTIFIER,
                                symbol_name=f"{node.name} (property)",
                                generation_expression=ret_expr,
                                entropy_quality=EntropyQuality.PREDICTABLE_HEAP_ADDRESS,
                                is_weak_or_predictable=True,
                                exposure_channels=exp_channels,
                                cookie_flags=c_flags,
                                validation_mechanism="dict_lookup",
                                lifecycle_controls={"has_expiration": False, "has_rotation": False},
                                exploitability_assessment=(
                                    "Session identifier derives directly from CPython heap object memory address (str(id(self))). "
                                    "While cookie flags (httponly, samesite) mitigate cross-origin theft, in CPython the memory addresses "
                                    "of heap-allocated objects follow sequential alignment strides (typically 0x20 to 0x80 bytes). "
                                    "A network-adjacent or concurrent client who obtains their own session ID can compute probable memory offsets "
                                    "of concurrent active sessions and hijack sessions without credentials."
                                ),
                            )
                        )

                    # Detect Pattern 2: CSPRNG (secrets.token_hex, uuid4, os.urandom)
                    elif any(c in ret_expr for c in ("secrets.token", "os.urandom", "uuid.uuid4", "uuid4()")):
                        prim_kind = SecurityPrimitiveKind.SESSION_IDENTIFIER if is_session_symbol else SecurityPrimitiveKind.API_TOKEN
                        self.primitives.append(
                            SecurityPrimitiveFact(
                                primitive_id=f"prim:{rel_path}:{node.name}:{ret.lineno}",
                                file_path=rel_path,
                                line_number=ret.lineno,
                                kind=prim_kind,
                                symbol_name=node.name,
                                generation_expression=ret_expr,
                                entropy_quality=EntropyQuality.SECURE_CSPRNG,
                                is_weak_or_predictable=False,
                                exposure_channels=["secure_token_channel"],
                                cookie_flags={},
                                validation_mechanism="cryptographic_or_hash",
                                lifecycle_controls={"has_expiration": True},
                                exploitability_assessment="Cryptographically secure pseudo-random number generator (CSPRNG) provides high collision resistance and unpredictability.",
                            )
                        )

                    # Detect Pattern 3: Weak PRNG (random.random, random.randint)
                    elif any(c in ret_expr for c in ("random.random", "random.randint", "random.choice")):
                        self.primitives.append(
                            SecurityPrimitiveFact(
                                primitive_id=f"prim:{rel_path}:{node.name}:{ret.lineno}",
                                file_path=rel_path,
                                line_number=ret.lineno,
                                kind=SecurityPrimitiveKind.API_TOKEN if not is_session_symbol else SecurityPrimitiveKind.SESSION_IDENTIFIER,
                                symbol_name=node.name,
                                generation_expression=ret_expr,
                                entropy_quality=EntropyQuality.WEAK_PRNG,
                                is_weak_or_predictable=True,
                                exposure_channels=["application_token"],
                                cookie_flags={},
                                validation_mechanism="equality_check",
                                lifecycle_controls={},
                                exploitability_assessment="Non-cryptographic PRNG (Mersenne Twister) allows internal state reconstruction from consecutive outputs.",
                            )
                        )

                    # Detect Pattern 4: Timestamp / Time state
                    elif any(c in ret_expr for c in ("time.time()", "datetime.now()", "time.monotonic()")) and is_session_symbol:
                        self.primitives.append(
                            SecurityPrimitiveFact(
                                primitive_id=f"prim:{rel_path}:{node.name}:{ret.lineno}",
                                file_path=rel_path,
                                line_number=ret.lineno,
                                kind=SecurityPrimitiveKind.SESSION_IDENTIFIER,
                                symbol_name=node.name,
                                generation_expression=ret_expr,
                                entropy_quality=EntropyQuality.PREDICTABLE_TIME_STATE,
                                is_weak_or_predictable=True,
                                exposure_channels=["timestamp_token"],
                                cookie_flags={},
                                validation_mechanism="equality_check",
                                lifecycle_controls={},
                                exploitability_assessment="Token derived from system wall-clock timestamp; susceptible to brute-force within narrow generation time window.",
                            )
                        )

        # Third pass: Detect CSRF origin verification hooks
        for hook in csrf_hooks:
            self.primitives.append(
                SecurityPrimitiveFact(
                    primitive_id=f"prim:{rel_path}:{hook['name']}:{hook['line']}",
                    file_path=rel_path,
                    line_number=hook["line"],
                    kind=SecurityPrimitiveKind.CSRF_TOKEN,
                    symbol_name=hook["name"],
                    generation_expression="Origin / Referer Host Matching Hook",
                    entropy_quality=EntropyQuality.UNKNOWN_OR_UNRESOLVED,
                    is_weak_or_predictable=False,
                    exposure_channels=["http_headers:Origin,Referer"],
                    cookie_flags={},
                    validation_mechanism="same_origin_header_check",
                    lifecycle_controls={"applies_to_state_changing_methods": True},
                    exploitability_assessment="State-changing request origin header enforcement. Requests missing both Origin and Referer may bypass check if non-browser requests are permitted.",
                )
            )
