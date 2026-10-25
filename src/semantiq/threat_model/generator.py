"""Codebase threat modeling and architecture extraction engine."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from semantiq.models import (
    Asset,
    EntryPoint,
    SensitiveOperation,
    ThreatModel,
    TrustBoundary,
)

ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}


class ThreatModelExtractor:
    """Extracts architectural threat model components deterministically from source code."""

    def __init__(self, repository_root: Path) -> None:
        self.repository_root = repository_root

    def build_threat_model(
        self,
        in_scope_files: list[str],
        app_name: str | None = None,
    ) -> ThreatModel:
        """Construct a structured threat model from scanned files."""
        name = app_name or self.repository_root.name
        assets = [
            Asset(name="Application Source Code", description="Core business logic and proprietary algorithms", criticality="high"),
            Asset(name="Database & Data Store", description="User records, application state, and persistent data", criticality="critical"),
            Asset(name="Authentication Credentials & Tokens", description="Session cookies, API keys, and private tokens", criticality="critical"),
            Asset(name="Host Environment & Execution Privileges", description="Underlying operating system shell, filesystem, and runtime environment", criticality="critical"),
        ]

        entry_points: list[EntryPoint] = []
        sensitive_ops: list[SensitiveOperation] = []

        for rel_file in in_scope_files:
            full_path = self.repository_root / rel_file
            if not full_path.exists() or not full_path.is_file():
                continue

            # Python files
            if rel_file.endswith(".py"):
                self._inspect_python_file(rel_file, full_path, entry_points, sensitive_ops)

            # JS/TS files
            elif rel_file.endswith((".js", ".ts", ".jsx", ".tsx")):
                self._inspect_js_file(rel_file, full_path, entry_points, sensitive_ops)

        # Standard trust boundaries
        trust_boundaries = [
            TrustBoundary(
                name="Network / Public Boundary",
                outer_zone="Public Internet / Untrusted Clients",
                inner_zone="Application Web Services",
                controls=["TLS/HTTPS Termination", "Rate Limiting", "Input Validation"],
            ),
            TrustBoundary(
                name="Authentication / Privilege Boundary",
                outer_zone="Unauthenticated Visitors",
                inner_zone="Authenticated User Sessions",
                controls=["Session Cookies", "JWT Verification", "Password Hashing"],
            ),
            TrustBoundary(
                name="System / OS Boundary",
                outer_zone="Application Runtime",
                inner_zone="Host Operating System",
                controls=["Least Privilege User", "Process Sandboxing", "Filesystem Permissions"],
            ),
        ]

        security_assumptions = [
            "Network traffic between clients and frontend gateway is encrypted via TLS.",
            "Database server credentials and secrets are supplied securely via environment variables or secret managers.",
            "Host operating system enforces user and group file isolation.",
        ]

        manual_review_areas = [
            "Custom authentication and authorization permission decorators.",
            "Dynamic file upload, parsing, and decompression routines.",
            "External webhook and third-party API integration consumers.",
        ]

        return ThreatModel(
            application_name=name,
            repository_path=str(self.repository_root),
            assets=assets,
            entry_points=entry_points,
            trust_boundaries=trust_boundaries,
            sensitive_operations=sensitive_ops,
            security_assumptions=security_assumptions,
            manual_review_areas=manual_review_areas,
        )

    def _inspect_python_file(
        self,
        rel_file: str,
        full_path: Path,
        entry_points: list[EntryPoint],
        sensitive_ops: list[SensitiveOperation],
    ) -> None:
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=rel_file)
        except Exception:
            return

        for node in ast.walk(tree):
            # Check function decorators for HTTP routes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                        elif isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Name):
                        dec_name = dec.id

                    if dec_name.lower() in ROUTE_DECORATORS:
                        entry_points.append(
                            EntryPoint(
                                identifier=f"{rel_file}:{node.name}",
                                kind="http_route",
                                file_path=rel_file,
                                line_number=node.lineno,
                                auth_required=any("auth" in getattr(d, "id", "").lower() for d in node.decorator_list if isinstance(d, ast.Name)),
                                description=f"HTTP endpoint handler {node.name} via @{dec_name}",
                            )
                        )

            # Check calls for sensitive operations
            if isinstance(node, ast.Call):
                call_str = ""
                if isinstance(node.func, ast.Attribute):
                    call_str = node.func.attr
                elif isinstance(node.func, ast.Name):
                    call_str = node.func.id

                lineno = getattr(node, "lineno", 1)
                if call_str in {"execute", "executemany"}:
                    sensitive_ops.append(
                        SensitiveOperation(
                            name=f"Database Query ({call_str})",
                            kind="db_write",
                            file_path=rel_file,
                            line_number=lineno,
                            description="Executes direct database queries",
                        )
                    )
                elif call_str in {"run", "Popen", "system"}:
                    sensitive_ops.append(
                        SensitiveOperation(
                            name=f"Subprocess Execution ({call_str})",
                            kind="shell_exec",
                            file_path=rel_file,
                            line_number=lineno,
                            description="Executes operating system processes",
                        )
                    )

    def _inspect_js_file(
        self,
        rel_file: str,
        full_path: Path,
        entry_points: list[EntryPoint],
        sensitive_ops: list[SensitiveOperation],
    ) -> None:
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            return

        route_re = re.compile(r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
        db_re = re.compile(r"""\.(?:query|raw|execute)\s*\(""", re.IGNORECASE)
        exec_re = re.compile(r"""(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(""", re.IGNORECASE)

        for idx, line in enumerate(lines, start=1):
            if m := route_re.search(line):
                method, path_str = m.group(1).upper(), m.group(2)
                entry_points.append(
                    EntryPoint(
                        identifier=f"{method} {path_str}",
                        kind="http_route",
                        file_path=rel_file,
                        line_number=idx,
                        description=f"Express route {method} {path_str}",
                    )
                )
            if db_re.search(line):
                sensitive_ops.append(
                    SensitiveOperation(
                        name="Database Query Execution",
                        kind="db_write",
                        file_path=rel_file,
                        line_number=idx,
                        description="Executes SQL query via database client",
                    )
                )
            if exec_re.search(line):
                sensitive_ops.append(
                    SensitiveOperation(
                        name="Child Process Execution",
                        kind="shell_exec",
                        file_path=rel_file,
                        line_number=idx,
                        description="Spawns host subprocess",
                    )
                )
