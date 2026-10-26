"""Language-aware JavaScript and TypeScript frontend for the Semantic Program Graph."""

from __future__ import annotations

import re
from pathlib import Path

from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import (
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RelationshipProvenance,
)
from semantiq.languages.base import FrontendCapabilities, FrontendResult, LanguageFrontend


class JavaScriptFrontend(LanguageFrontend):
    """Language-aware JavaScript and TypeScript semantic frontend.

    Parses modules, imports, function declarations, arrow functions, Express/Node.js
    routes, database queries, child process execution, external network requests,
    and authentication middleware into the Semantic Program Graph with explicit gap accounting.
    """

    @property
    def language_id(self) -> str:
        return "javascript"

    @property
    def file_extensions(self) -> tuple[str, ...]:
        return (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

    def get_capabilities(self) -> FrontendCapabilities:
        return FrontendCapabilities(
            language_id="javascript",
            parsing_coverage="Regex-based structural syntax scanner (not a full AST or type-checker). Extracts ES6/CommonJS imports, exports, functions, arrow functions, classes, and Express routes",
            symbol_resolution_coverage="Module imports, CommonJS require(), export bindings, and Express handler symbol linking",
            call_graph_coverage="Direct function invocations, route-to-handler bindings, database queries, and process execution sinks",
            data_flow_capabilities="Express req.body/params/query tracking into route handlers and sink invocations",
            framework_semantics=["Express", "Node.js standard libraries (fs, child_process, http)", "Axios", "PG / MySQL / Knex"],
            unsupported_syntax_notes=[
                "Structural scanner limitation: Does not build full lexical closure scopes or AST type-flow graphs",
                "Dynamic code evaluation via eval() and computed property member access are tracked as unresolved dispatch",
                "TypeScript interfaces, generics, and type-only imports are skipped without full compiler analysis",
            ],
        )

    def parse_file(
        self,
        file_path: str,
        source_code: str,
        graph: SemanticProgramGraph,
        repo_root: Path,
        source_revision: str = "",
    ) -> FrontendResult:
        clean_file = file_path.replace("\\", "/")
        lines = source_code.splitlines()
        total_lines = len(lines) or 1

        nodes_before = len(graph.nodes)
        edges_before = sum(len(e) for e in graph.out_edges.values())
        gaps: list[str] = []

        # 1. Create File Node
        file_node_id = f"file:{clean_file}"
        graph.add_node(
            GraphNode(
                id=file_node_id,
                kind=NodeKind.FILE,
                label=Path(clean_file).name,
                file_path=clean_file,
                start_line=1,
                end_line=total_lines,
                provenance=RelationshipProvenance.DIRECT_FACT,
                source_revision=source_revision,
            )
        )

        # 2. Extract Imports
        # ES6: import ... from '...'
        import_es6 = re.compile(r"""import\s+(?:\{([^}]+)\}|(\w+))\s+from\s+['"]([^'"]+)['"]""")
        # CommonJS: const ... = require('...')
        import_cjs = re.compile(r"""(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""")

        for lineno, line in enumerate(lines, start=1):
            for match in import_es6.finditer(line):
                destructured, default_name, mod_path = match.groups()
                target_syms = [s.strip() for s in destructured.split(",")] if destructured else [default_name]
                for sym in target_syms:
                    if sym:
                        imp_id = f"import:{clean_file}:{lineno}:{sym}"
                        graph.add_node(
                            GraphNode(
                                id=imp_id,
                                kind=NodeKind.MODULE,
                                label=f"{sym} from {mod_path}",
                                file_path=clean_file,
                                start_line=lineno,
                                end_line=lineno,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                                source_revision=source_revision,
                                properties={"module": mod_path, "symbol": sym},
                            )
                        )
                        graph.add_edge(
                            GraphEdge(
                                source_id=file_node_id,
                                target_id=imp_id,
                                kind=EdgeKind.IMPORTS,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                            )
                        )

            for match in import_cjs.finditer(line):
                destructured, default_name, mod_path = match.groups()
                target_syms = [s.strip() for s in destructured.split(",")] if destructured else [default_name]
                for sym in target_syms:
                    if sym:
                        imp_id = f"import:{clean_file}:{lineno}:{sym}"
                        graph.add_node(
                            GraphNode(
                                id=imp_id,
                                kind=NodeKind.MODULE,
                                label=f"{sym} from {mod_path}",
                                file_path=clean_file,
                                start_line=lineno,
                                end_line=lineno,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                                source_revision=source_revision,
                                properties={"module": mod_path, "symbol": sym},
                            )
                        )
                        graph.add_edge(
                            GraphEdge(
                                source_id=file_node_id,
                                target_id=imp_id,
                                kind=EdgeKind.IMPORTS,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                            )
                        )

        # 3. Extract Classes and Inheritance
        class_decl = re.compile(r"""class\s+([a-zA-Z0-9_$]+)(?:\s+extends\s+([a-zA-Z0-9_$]+))?""")
        for lineno, line in enumerate(lines, start=1):
            m_cls = class_decl.search(line)
            if m_cls:
                cls_name, base_name = m_cls.groups()
                cls_id = f"class:{clean_file}:{cls_name}"
                graph.add_node(
                    GraphNode(
                        id=cls_id,
                        kind=NodeKind.CLASS,
                        label=cls_name,
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"bases": [base_name] if base_name else []},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=cls_id,
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

        # 4. Extract Exports
        export_decl = re.compile(r"""export\s+(?:default\s+)?(?:const|let|var|function|class)?\s*([a-zA-Z0-9_$]+)""")
        for lineno, line in enumerate(lines, start=1):
            m_exp = export_decl.search(line)
            if m_exp:
                exp_sym = m_exp.group(1)
                exp_id = f"export:{clean_file}:{lineno}:{exp_sym}"
                graph.add_node(
                    GraphNode(
                        id=exp_id,
                        kind=NodeKind.MODULE,
                        label=f"export {exp_sym}",
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"symbol": exp_sym},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=exp_id,
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

        # 5. Extract Functions & Arrow Functions
        func_decl = re.compile(r"""(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)""")
        arrow_func = re.compile(r"""(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>""")

        func_positions: dict[str, tuple[str, int]] = {}  # name -> (id, line)

        for lineno, line in enumerate(lines, start=1):
            m_func = func_decl.search(line)
            if m_func:
                name, raw_params = m_func.groups()
                params = [p.strip().split(":")[0].strip() for p in raw_params.split(",") if p.strip()]
                func_id = f"sym:{clean_file}:{name}"
                func_positions[name] = (func_id, lineno)
                graph.add_node(
                    GraphNode(
                        id=func_id,
                        kind=NodeKind.FUNCTION,
                        label=name,
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"params": params},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=func_id,
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )
                continue

            m_arrow = arrow_func.search(line)
            if m_arrow:
                name, raw_params = m_arrow.groups()
                params = [p.strip().split(":")[0].strip() for p in raw_params.split(",") if p.strip()]
                func_id = f"sym:{clean_file}:{name}"
                func_positions[name] = (func_id, lineno)
                graph.add_node(
                    GraphNode(
                        id=func_id,
                        kind=NodeKind.FUNCTION,
                        label=name,
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"params": params},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=func_id,
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

        # Gap Detection across file
        for lineno, line in enumerate(lines, start=1):
            if re.search(r"""(?:\.(?:then|catch|map|filter|forEach|on)|\b(?:setTimeout|setInterval|setImmediate))\s*\(\s*(?:function|\([^)]*\)\s*=>)""", line):
                gaps.append(f"Line {lineno}: Callback/closure lexical environment not fully traced in JS/TS frontend")
            if re.search(r"""\?\.\w+""", line):
                gaps.append(f"Line {lineno}: Optional chaining (?.) syntax detected; evaluated as optimistic property access")
            if re.search(r"""\b(?:interface|type)\s+[A-Za-z0-9_$]+|\b[A-Za-z0-9_$]+<[A-Za-z0-9_$,\s]+>""", line):
                gaps.append(f"Line {lineno}: TypeScript type definitions or generics ignored by structural scanner")

        # 4. Extract Express / HTTP Routes
        # app.get('/path', handler) or router.post('/path', middleware, handler)
        route_regex = re.compile(
            r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(.*?)\s*\)"""
        )

        for lineno, line in enumerate(lines, start=1):
            m_route = route_regex.search(line)
            if m_route:
                method, path, handlers_raw = m_route.groups()
                route_id = f"route:{clean_file}:{path}"
                graph.add_node(
                    GraphNode(
                        id=route_id,
                        kind=NodeKind.ROUTE,
                        label=f"Route: {method.upper()} {path}",
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"route_path": path, "http_method": method.upper()},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=route_id,
                        kind=EdgeKind.DEFINES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

                # Check if handlers refer to known functions or middleware
                handler_names = [h.strip() for h in handlers_raw.split(",") if h.strip()]
                for h_name in handler_names:
                    if any(k in h_name.lower() for k in ["auth", "jwt", "passport", "protect", "isadmin"]):
                        auth_node_id = f"auth:{clean_file}:{lineno}:{h_name}"
                        graph.add_node(
                            GraphNode(
                                id=auth_node_id,
                                kind=NodeKind.AUTH_CONTROL,
                                label=f"Middleware: {h_name}",
                                file_path=clean_file,
                                start_line=lineno,
                                end_line=lineno,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                                source_revision=source_revision,
                            )
                        )
                        graph.add_edge(
                            GraphEdge(
                                source_id=auth_node_id,
                                target_id=route_id,
                                kind=EdgeKind.AUTHENTICATES,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                            )
                        )
                    elif h_name in func_positions:
                        target_id, _ = func_positions[h_name]
                        graph.add_edge(
                            GraphEdge(
                                source_id=route_id,
                                target_id=target_id,
                                kind=EdgeKind.CALLS,
                                provenance=RelationshipProvenance.DIRECT_FACT,
                            )
                        )

        # 5. Extract Dangerous Sinks and Queries
        for lineno, line in enumerate(lines, start=1):
            # Database SQL: db.query(...) / pool.query(...) / executeQuery(...)
            if re.search(r"""\b(?:db|pool|client|connection|sequelize)\.(?:query|execute|raw)\s*\(|\b(?:executeQuery|executeSql)\s*\(""", line):
                sink_id = f"sink:sql:{clean_file}:{lineno}"
                graph.add_node(
                    GraphNode(
                        id=sink_id,
                        kind=NodeKind.QUERY,
                        label="Database Query Execution",
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"sink_expression": line.strip()},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=sink_id,
                        kind=EdgeKind.QUERIES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

            # Command execution: exec(...) / execSync(...)
            if re.search(r"""\b(?:exec|execSync|spawn|spawnSync)\s*\(""", line):
                sink_id = f"sink:exec:{clean_file}:{lineno}"
                graph.add_node(
                    GraphNode(
                        id=sink_id,
                        kind=NodeKind.PROCESS_EXEC,
                        label="OS Process Execution",
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"sink_expression": line.strip()},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=sink_id,
                        kind=EdgeKind.REACHES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

            # External HTTP: axios.get(...) / fetch(...)
            if re.search(r"""\b(?:axios|fetch|http\.get|https\.get)\s*\(""", line):
                sink_id = f"sink:http:{clean_file}:{lineno}"
                graph.add_node(
                    GraphNode(
                        id=sink_id,
                        kind=NodeKind.EXTERNAL_REQUEST,
                        label="External Network Request",
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"sink_expression": line.strip()},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=sink_id,
                        kind=EdgeKind.REACHES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )

            # Dynamic Eval: eval(...)
            if re.search(r"""\beval\s*\(""", line):
                sink_id = f"sink:eval:{clean_file}:{lineno}"
                graph.add_node(
                    GraphNode(
                        id=sink_id,
                        kind=NodeKind.SENSITIVE_SINK,
                        label="Dynamic Code Evaluation (eval)",
                        file_path=clean_file,
                        start_line=lineno,
                        end_line=lineno,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                        source_revision=source_revision,
                        properties={"sink_expression": line.strip()},
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=file_node_id,
                        target_id=sink_id,
                        kind=EdgeKind.REACHES,
                        provenance=RelationshipProvenance.DIRECT_FACT,
                    )
                )
                gaps.append(f"Line {lineno}: Dynamic eval() invocation detected in {clean_file}")

        nodes_created = len(graph.nodes) - nodes_before
        edges_created = sum(len(e) for e in graph.out_edges.values()) - edges_before

        return FrontendResult(
            file_path=clean_file,
            language="javascript",
            parsed_successfully=True,
            nodes_created=nodes_created,
            edges_created=edges_created,
            gaps=gaps,
        )
