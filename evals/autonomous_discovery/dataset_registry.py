"""Target Dataset Registry for Autonomous Deep Vulnerability Discovery.

Defines held-out target repositories, pinned commit revisions, architectural scopes,
and ground-truth vulnerability specifications for evaluating Phase 5 discovery capabilities.

Targets:
1. NASA-AMMOS/AIT-GUI: Historical Baseline Target (b9df6fc551ad6788ffd16e2451492dce12ead9cc)
2. pyload: Held-Out Production Target - Web Download Manager (1b12dc7f348db8c144e0f39215680415e90ca4d2)
3. GitPython: Held-Out Production Target - Git Library & CLI Wrapper (3481da9618e69063464c94447167d83bd45505a9)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from semantiq.discovery.hypothesis import DeepVulnerabilityClass
from semantiq.models import SeverityLevel, VulnerabilityCategory


@dataclass
class GroundTruthVulnerability:
    """Formal specification of a known vulnerability in an evaluation target."""

    vuln_id: str
    title: str
    category: VulnerabilityCategory
    vuln_class: DeepVulnerabilityClass
    cwe_ids: list[str]
    target_symbol: str
    file_path: str
    sink_operation: str
    root_cause: str
    expected_severity: SeverityLevel


@dataclass
class TargetRepositorySpec:
    """Configuration and ground-truth metadata for a benchmark repository."""

    repo_id: str
    name: str
    root_path: Path
    pinned_commit: str
    architecture_style: str
    description: str
    in_scope_subpaths: list[str]
    ground_truth: list[GroundTruthVulnerability] = field(default_factory=list)


DATASET_REGISTRY: dict[str, TargetRepositorySpec] = {
    "nasa_ait_gui": TargetRepositorySpec(
        repo_id="nasa_ait_gui",
        name="NASA-AMMOS/AIT-GUI",
        root_path=Path("E:/bbp/NASA-AMMOS/AIT-GUI"),
        pinned_commit="b9df6fc551ad6788ffd16e2451492dce12ead9cc",
        architecture_style="Bottle Web Application",
        description="Ground control web interface for autonomous flight and science telemetry.",
        in_scope_subpaths=["ait/gui"],
        ground_truth=[
            GroundTruthVulnerability(
                vuln_id="GT-AIT-01",
                title="Command Injection via handle_cmd",
                category=VulnerabilityCategory.COMMAND_INJECTION,
                vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
                cwe_ids=["CWE-78"],
                target_symbol="handle_cmd",
                file_path="ait/gui/__init__.py",
                sink_operation="subprocess.Popen",
                root_cause="Unescaped shell argument concatenation during command dispatch",
                expected_severity=SeverityLevel.CRITICAL,
            ),
            GroundTruthVulnerability(
                vuln_id="GT-AIT-02",
                title="Arbitrary Script Execution via handle_script_run_put",
                category=VulnerabilityCategory.COMMAND_INJECTION,
                vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
                cwe_ids=["CWE-78", "CWE-94"],
                target_symbol="handle_script_run_put",
                file_path="ait/gui/__init__.py",
                sink_operation="bg_exec_seq",
                root_cause="Direct execution of user-specified script path in background process",
                expected_severity=SeverityLevel.HIGH,
            ),
            GroundTruthVulnerability(
                vuln_id="GT-AIT-03",
                title="Weak Session Token Predictability via id(self)",
                category=VulnerabilityCategory.INSECURE_CRYPTO,
                vuln_class=DeepVulnerabilityClass.AUTHENTICATION_SESSION_SECURITY,
                cwe_ids=["CWE-330", "CWE-384"],
                target_symbol="SessionStore",
                file_path="ait/gui/__init__.py",
                sink_operation="id(self)",
                root_cause="Session identifier leaks internal Python object heap address",
                expected_severity=SeverityLevel.HIGH,
            ),
            GroundTruthVulnerability(
                vuln_id="GT-AIT-04",
                title="Arbitrary Path Traversal in Static File Serving",
                category=VulnerabilityCategory.PATH_TRAVERSAL,
                vuln_class=DeepVulnerabilityClass.FILE_RESOURCE_HANDLING,
                cwe_ids=["CWE-22"],
                target_symbol="handle_scripts_load",
                file_path="ait/gui/__init__.py",
                sink_operation="os.path.join",
                root_cause="File path concatenation lacking root directory containment enforcement",
                expected_severity=SeverityLevel.HIGH,
            ),
        ],
    ),
    "pyload": TargetRepositorySpec(
        repo_id="pyload",
        name="pyload/pyload",
        root_path=Path("E:/bbp/pyload"),
        pinned_commit="1b12dc7f348db8c144e0f39215680415e90ca4d2",
        architecture_style="Flask Web Application & Modular Plugin System",
        description="Production download manager featuring modular plugin architecture, web UI, and archive extraction.",
        in_scope_subpaths=["src/pyload"],
        ground_truth=[
            GroundTruthVulnerability(
                vuln_id="GT-PYLOAD-01",
                title="Unsafe Plugin Dynamic Code Execution via exec_module",
                category=VulnerabilityCategory.CODE_INJECTION,
                vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
                cwe_ids=["CWE-94"],
                target_symbol="CustomModuleLoader.exec_module",
                file_path="src/pyload/core/managers/plugin_manager.py",
                sink_operation="exec(code, module.__dict__)",
                root_cause="Dynamically executes Python source code from user-controlled plugin directory at import time",
                expected_severity=SeverityLevel.HIGH,
            ),
            GroundTruthVulnerability(
                vuln_id="GT-PYLOAD-02",
                title="Archive Extraction Symlink / Path Traversal Escape",
                category=VulnerabilityCategory.PATH_TRAVERSAL,
                vuln_class=DeepVulnerabilityClass.FILE_RESOURCE_HANDLING,
                cwe_ids=["CWE-22", "CWE-59"],
                target_symbol="extract",
                file_path="src/pyload/plugins/extractors/SevenZip.py",
                sink_operation="extract",
                root_cause="Extraction path check fails to prevent symlink traversal to outside directory",
                expected_severity=SeverityLevel.HIGH,
            ),
            GroundTruthVulnerability(
                vuln_id="GT-PYLOAD-03",
                title="Unauthenticated Endpoint Access & Privilege Exposure",
                category=VulnerabilityCategory.AUTHORIZATION_BYPASS,
                vuln_class=DeepVulnerabilityClass.AUTHORIZATION_ACCESS_CONTROL,
                cwe_ids=["CWE-862", "CWE-285"],
                target_symbol="package",
                file_path="src/pyload/webui/app/blueprints/json_blueprint.py",
                sink_operation="endpoint_dispatch",
                root_cause="Web routes permit unauthenticated interaction with download management state",
                expected_severity=SeverityLevel.MEDIUM,
            ),
        ],
    ),
    "gitpython": TargetRepositorySpec(
        repo_id="gitpython",
        name="gitpython-developers/GitPython",
        root_path=Path("E:/bbp/GitPython"),
        pinned_commit="3481da9618e69063464c94447167d83bd45505a9",
        architecture_style="Python Library & Git CLI Wrapper",
        description="Python library for interacting with Git repositories via process invocation and object trees.",
        in_scope_subpaths=["git"],
        ground_truth=[
            GroundTruthVulnerability(
                vuln_id="GT-GIT-01",
                title="Command Injection via Remote Protocol URL (ext::)",
                category=VulnerabilityCategory.COMMAND_INJECTION,
                vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
                cwe_ids=["CWE-78", "CWE-88"],
                target_symbol="Git._call_process",
                file_path="git/cmd.py",
                sink_operation="subprocess.Popen",
                root_cause="Protocol handling allows ext:: remote URLs to execute shell commands during clone/fetch",
                expected_severity=SeverityLevel.CRITICAL,
            ),
            GroundTruthVulnerability(
                vuln_id="GT-GIT-02",
                title="Arbitrary Command Execution via Subprocess Argument Injection",
                category=VulnerabilityCategory.COMMAND_INJECTION,
                vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
                cwe_ids=["CWE-88"],
                target_symbol="Git.execute",
                file_path="git/cmd.py",
                sink_operation="subprocess.Popen",
                root_cause="Git command invocation passes unquoted CLI flags or option parameters",
                expected_severity=SeverityLevel.HIGH,
            ),
        ],
    ),
}

