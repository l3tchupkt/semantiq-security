"""Runtime permission boundary and execution sandbox for skills.

Enforces strict capability constraints (filesystem access, process execution,
network boundaries, and graph queries) based on the skill's declared contract.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from semantiq.exceptions import SemantiqError
from semantiq.repository.safepath import resolve_safe_path
from semantiq.skills.contract import SkillPermission

logger = logging.getLogger("semantiq.skills.sandbox")

DEFAULT_DENIED_FILE_PATTERNS = [
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
    ".git/config",
    ".git/credentials",
]


class SkillPermissionDeniedError(SemantiqError):
    """Raised when a skill attempts an operation outside its granted permissions."""

    def __init__(self, skill_id: str, permission: SkillPermission, detail: str = "") -> None:
        self.skill_id = skill_id
        self.permission = permission
        msg = f"Permission '{permission.value}' denied for skill '{skill_id}'"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class SkillSandbox:
    """Runtime enforcement boundary isolating a skill's execution."""

    def __init__(
        self,
        skill_id: str,
        repository_root: Path,
        granted_permissions: set[SkillPermission],
        denied_patterns: list[str] | None = None,
    ) -> None:
        self.skill_id = skill_id
        self.repository_root = repository_root.resolve()
        self.granted_permissions = set(granted_permissions)
        self.denied_patterns = (
            denied_patterns if denied_patterns is not None else list(DEFAULT_DENIED_FILE_PATTERNS)
        )
        self._audit_log: list[dict[str, Any]] = []

    def check_permission(self, permission: SkillPermission, detail: str = "") -> None:
        """Verify that a permission has been granted; raise SkillPermissionDeniedError if not."""
        if permission not in self.granted_permissions:
            logger.warning(
                "Skill '%s' attempted unauthorized operation requiring '%s'",
                self.skill_id,
                permission.value,
            )
            self._audit_log.append(
                {"event": "permission_denied", "permission": permission.value, "detail": detail}
            )
            raise SkillPermissionDeniedError(self.skill_id, permission, detail)

    def resolve_read_path(self, target_path: str | Path) -> Path:
        """Resolve a readable file path while enforcing filesystem boundaries and denials."""
        self.check_permission(SkillPermission.FILESYSTEM_READ, f"read {target_path}")

        # Enforce containment within repository root (rejects traversal, symlink escape, NTFS streams)
        safe = resolve_safe_path(self.repository_root, target_path)

        # Check against denied sensitive patterns
        rel = str(safe.relative_to(self.repository_root)).replace("\\", "/")
        for pattern in self.denied_patterns:
            if pattern in rel or safe.name == pattern:
                msg = f"Access to sensitive path pattern '{pattern}' is blocked by sandbox policy"
                logger.warning(
                    "Sandbox blocked access to sensitive pattern '%s' for '%s'",
                    pattern,
                    self.skill_id,
                )
                self._audit_log.append(
                    {"event": "sensitive_path_blocked", "path": rel, "pattern": pattern}
                )
                raise SkillPermissionDeniedError(
                    self.skill_id, SkillPermission.FILESYSTEM_READ, msg
                )

        self._audit_log.append({"event": "read_allowed", "path": rel})
        return safe

    def resolve_write_path(self, target_path: str | Path) -> Path:
        """Resolve a writable path within authorized staging locations."""
        self.check_permission(SkillPermission.FILESYSTEM_WRITE, f"write {target_path}")

        safe = resolve_safe_path(self.repository_root, target_path)
        rel = str(safe.relative_to(self.repository_root)).replace("\\", "/")

        self._audit_log.append({"event": "write_allowed", "path": rel})
        return safe

    def execute_command(
        self,
        cmd: list[str],
        timeout: float = 30.0,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a controlled command strictly without shell=True."""
        self.check_permission(SkillPermission.PROCESS_EXECUTION, f"execute {' '.join(cmd[:3])}")

        target_cwd = cwd or self.repository_root
        logger.info("Sandbox executing command for skill '%s': %s", self.skill_id, cmd[:3])

        self._audit_log.append({"event": "process_execution", "cmd": cmd[:5]})
        return subprocess.run(
            cmd,
            cwd=target_cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )

    def verify_graph_access(self) -> None:
        """Verify that the skill has permission to query the Semantic Program Graph."""
        self.check_permission(SkillPermission.GRAPH_QUERY, "Semantic Program Graph access")

    def verify_network_access(self, destination: str = "") -> None:
        """Verify that the skill is authorized to perform external network I/O."""
        self.check_permission(SkillPermission.NETWORK_ACCESS, f"network access to {destination}")

    def verify_mcp_tool_access(self, tool_name: str) -> None:
        """Verify permission to call an MCP tool."""
        self.check_permission(SkillPermission.MCP_TOOLS, f"invoke tool {tool_name}")

    @property
    def audit_trail(self) -> list[dict[str, Any]]:
        """Retrieve copy of all sandbox authorization events."""
        return list(self._audit_log)
