"""Dynamic Investigation Packet Planner.

Partitions a target repository into discrete, non-overlapping investigation packets
grounded in real repository architecture: routes, sensitive sinks, auth boundaries,
unresolved dispatches, and uncovered graph regions.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import NodeKind
from semantiq.models import ThreatModel
from semantiq.orchestration.packet import InvestigationPacket, PacketDimension
from semantiq.skills.contract import SkillBudget, SkillPermission

logger = logging.getLogger(__name__)


class PacketPlanner:
    """Plans and generates balanced investigation packets from repository architecture."""

    def __init__(
        self,
        repository_root: Path,
        source_revision: str,
        scan_id: str,
        graph: SemanticProgramGraph | None = None,
        threat_model: ThreatModel | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.source_revision = source_revision
        self.scan_id = scan_id
        self._graph = graph
        self._threat_model = threat_model

    def get_or_build_graph(self, scoped_files: list[str]) -> SemanticProgramGraph:
        """Retrieve existing graph or construct one over scoped files."""
        if self._graph is not None:
            return self._graph
        builder = GraphBuilder(repo_root=self.repository_root, source_revision=self.source_revision)
        self._graph = builder.build(scoped_files).graph
        return self._graph

    def plan_investigation(
        self,
        target_files: list[str],
        max_packets_per_dimension: int = 5,
    ) -> list[InvestigationPacket]:
        """Dynamically generate investigation packets across architectural dimensions."""
        graph = self.get_or_build_graph(target_files)
        packets: list[InvestigationPacket] = []
        covered_files: set[str] = set()

        # 1. Dimension: Entrypoint Routes & External APIs
        route_nodes = graph.find_nodes(kind=NodeKind.ROUTE)
        if route_nodes:
            # Cluster routes by blueprint, path prefix, or file
            routes_by_prefix: dict[str, list[Any]] = defaultdict(list)
            for r in route_nodes:
                prefix = (
                    r.label.split("/")[1]
                    if "/" in r.label and len(r.label.split("/")) > 1
                    else "root"
                )
                routes_by_prefix[prefix].append(r)

            for prefix, r_nodes in list(routes_by_prefix.items())[:max_packets_per_dimension]:
                r_symbols = [r.label for r in r_nodes if r.label]
                r_files = sorted(list({r.file_path for r in r_nodes if r.file_path}))
                covered_files.update(r_files)
                pkt = InvestigationPacket.create(
                    scan_id=self.scan_id,
                    repository_root=self.repository_root,
                    source_revision=self.source_revision,
                    dimension=PacketDimension.ENTRYPOINT_ROUTE,
                    objective=f"Investigate HTTP API endpoints under route prefix '/{prefix}' for unauthorized access, parameter injection, and insecure handling.",
                    target_symbols=r_symbols,
                    target_files=r_files,
                    relevant_node_ids=[r.id for r in r_nodes],
                    assigned_skills=[
                        "sq.skill.finding_discovery",
                        "sq.skill.attack_path_analysis",
                        "sq.skill.adversarial_validation",
                    ],
                    permission_ceiling=[
                        SkillPermission.FILESYSTEM_READ,
                        SkillPermission.GRAPH_QUERY,
                    ],
                    budget=SkillBudget(max_turns=12, timeout_seconds=90.0, max_tokens=30000),
                )
                packets.append(pkt)

        # 2. Dimension: Sensitive Sinks (Execution, Path Traversal, Deserialization, SQL)
        sink_keywords = [
            "subprocess",
            "system",
            "popen",
            "exec",
            "eval",
            "pickle",
            "yaml",
            "open",
            "execute",
            "cursor",
            "query",
            "delete",
            "unlink",
            "rmtree",
            "dispatch",
        ]
        sink_nodes: list[Any] = []
        with_suppress = graph.find_nodes(kind=NodeKind.CALL_SITE)
        for c in with_suppress:
            if any(kw in c.label.lower() or kw in c.id.lower() for kw in sink_keywords):
                sink_nodes.append(c)

        if sink_nodes:
            sinks_by_category: dict[str, list[Any]] = defaultdict(list)
            for s in sink_nodes:
                cat = (
                    "cmd_exec"
                    if any(k in s.label.lower() for k in ["sub", "sys", "pop", "exec", "eval"])
                    else "resource_access"
                )
                sinks_by_category[cat].append(s)

            for cat, s_nodes in list(sinks_by_category.items())[:max_packets_per_dimension]:
                s_symbols = [s.label for s in s_nodes if s.label][:15]
                s_files = sorted(list({s.file_path for s in s_nodes if s.file_path}))[:10]
                covered_files.update(s_files)
                pkt = InvestigationPacket.create(
                    scan_id=self.scan_id,
                    repository_root=self.repository_root,
                    source_revision=self.source_revision,
                    dimension=PacketDimension.SENSITIVE_SINK,
                    objective=f"Analyze sensitive operation sinks ({cat}) for unvalidated dataflow from untrusted callers.",
                    target_symbols=s_symbols,
                    target_files=s_files,
                    relevant_node_ids=[s.id for s in s_nodes[:20]],
                    assigned_skills=[
                        "sq.skill.finding_discovery",
                        "sq.skill.attack_path_analysis",
                    ],
                    permission_ceiling=[
                        SkillPermission.FILESYSTEM_READ,
                        SkillPermission.GRAPH_QUERY,
                    ],
                    budget=SkillBudget(max_turns=10, timeout_seconds=60.0, max_tokens=25000),
                )
                packets.append(pkt)

        # 3. Dimension: Authentication & Authorization Boundaries
        auth_keywords = [
            "auth",
            "login",
            "perm",
            "session",
            "token",
            "jwt",
            "check_admin",
            "credential",
            "role",
        ]
        fn_nodes = graph.find_nodes(kind=NodeKind.FUNCTION)
        auth_nodes = [
            fn
            for fn in fn_nodes
            if any(ak in fn.label.lower() or ak in fn.id.lower() for ak in auth_keywords)
        ]
        if auth_nodes:
            auth_symbols = [a.label for a in auth_nodes if a.label][:10]
            auth_files = sorted(list({a.file_path for a in auth_nodes if a.file_path}))[:8]
            covered_files.update(auth_files)
            pkt = InvestigationPacket.create(
                scan_id=self.scan_id,
                repository_root=self.repository_root,
                source_revision=self.source_revision,
                dimension=PacketDimension.AUTH_BOUNDARY,
                objective="Evaluate authentication filters, permission assertions, and session checks for bypass vulnerabilities.",
                target_symbols=auth_symbols,
                target_files=auth_files,
                relevant_node_ids=[a.id for a in auth_nodes],
                assigned_skills=[
                    "sq.skill.threat_modeling",
                    "sq.skill.finding_discovery",
                ],
                permission_ceiling=[SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
                budget=SkillBudget(max_turns=8, timeout_seconds=45.0, max_tokens=20000),
            )
            packets.append(pkt)

        # 4. Dimension: Unresolved Dynamic Dispatches
        unresolved = graph.get_unresolved_dispatches()
        if unresolved:
            raw_files = [
                (
                    u.get("call_site", {}).get("file_path")
                    if isinstance(u.get("call_site"), dict)
                    else u.get("file_path")
                )
                for u in unresolved
            ]
            unres_files = sorted(list({f for f in raw_files if f}))[:10]
            unres_exprs = [
                str(u.get("call_expression") or u.get("expression") or "")
                for u in unresolved
                if u.get("call_expression") or u.get("expression")
            ][:10]
            covered_files.update(unres_files)
            pkt = InvestigationPacket.create(
                scan_id=self.scan_id,
                repository_root=self.repository_root,
                source_revision=self.source_revision,
                dimension=PacketDimension.UNRESOLVED_DISPATCH,
                objective="Investigate dynamic dispatch locations (getattr, indirect lookups) for controlled destination redirection or code execution.",
                target_symbols=unres_exprs,
                target_files=unres_files,
                assigned_skills=[
                    "sq.skill.finding_discovery",
                    "sq.skill.adversarial_validation",
                ],
                permission_ceiling=[SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
                budget=SkillBudget(max_turns=8, timeout_seconds=45.0, max_tokens=20000),
            )
            packets.append(pkt)

        # 5. Dimension: Uncovered Graph Regions / Remaining Files
        uncovered_files = sorted([f for f in target_files if f not in covered_files])
        if uncovered_files:
            # Chunk uncovered files into packets of at most 20 files each
            chunk_size = 20
            for i in range(
                0, min(len(uncovered_files), max_packets_per_dimension * chunk_size), chunk_size
            ):
                chunk = uncovered_files[i : i + chunk_size]
                pkt = InvestigationPacket.create(
                    scan_id=self.scan_id,
                    repository_root=self.repository_root,
                    source_revision=self.source_revision,
                    dimension=PacketDimension.UNCOVERED_GRAPH_REGION,
                    objective=f"Scan uncovered codebase modules (slice {i // chunk_size + 1}) for latent vulnerabilities.",
                    target_files=chunk,
                    assigned_skills=[
                        "sq.skill.finding_discovery",
                    ],
                    permission_ceiling=[SkillPermission.FILESYSTEM_READ],
                    budget=SkillBudget(max_turns=8, timeout_seconds=45.0, max_tokens=20000),
                )
                packets.append(pkt)

        # Fallback: if no packets were planned (e.g. empty graph), create one overall packet
        if not packets:
            packets.append(
                InvestigationPacket.create(
                    scan_id=self.scan_id,
                    repository_root=self.repository_root,
                    source_revision=self.source_revision,
                    dimension=PacketDimension.UNCOVERED_GRAPH_REGION,
                    objective="Perform general security discovery across target files.",
                    target_files=target_files[:30],
                    assigned_skills=[
                        "sq.skill.threat_modeling",
                        "sq.skill.finding_discovery",
                        "sq.skill.attack_path_analysis",
                        "sq.skill.adversarial_validation",
                    ],
                    permission_ceiling=[
                        SkillPermission.FILESYSTEM_READ,
                        SkillPermission.GRAPH_QUERY,
                    ],
                )
            )

        logger.info(
            "PacketPlanner generated %d investigation packets across dimensions: %s",
            len(packets),
            {p.dimension.value for p in packets},
        )
        return packets

    def create_followup_packet(
        self,
        parent_packet: InvestigationPacket,
        objective: str,
        target_files: list[str],
        target_symbols: list[str] | None = None,
        dimension: PacketDimension | None = None,
        assigned_skills: list[str] | None = None,
    ) -> InvestigationPacket:
        """Create a targeted follow-up packet connected to an unresolved parent finding or path."""
        return InvestigationPacket.create(
            scan_id=self.scan_id,
            repository_root=self.repository_root,
            source_revision=self.source_revision,
            dimension=dimension or parent_packet.dimension,
            objective=objective,
            target_symbols=target_symbols or parent_packet.target_symbols,
            target_files=target_files,
            assigned_skills=assigned_skills or parent_packet.assigned_skills,
            permission_ceiling=parent_packet.permission_ceiling,
            budget=parent_packet.budget,
            retry_policy=parent_packet.retry_policy,
            parent_packet_id=parent_packet.packet_id,
        )
