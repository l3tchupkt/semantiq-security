"""Tests auditing JavaScript/TypeScript frontend capabilities, heuristics, and syntax coverage gaps."""

from __future__ import annotations

from pathlib import Path

from semantiq.graph.graph import SemanticProgramGraph
from semantiq.graph.models import NodeKind
from semantiq.languages.javascript import JavaScriptFrontend


def test_javascript_frontend_heuristics_and_limitations() -> None:
    frontend = JavaScriptFrontend()
    caps = frontend.get_capabilities()

    # 1. Assert capabilities honestly disclose structural scanner limitation
    assert "Regex-based structural syntax scanner" in caps.parsing_coverage
    assert any("not build full lexical closure scopes" in note.lower() for note in caps.unsupported_syntax_notes)
    assert any("typescript interfaces, generics" in note.lower() for note in caps.unsupported_syntax_notes)

    # 2. Test comprehensive JS/TS source code with standard and advanced constructs
    sample_js = """
    import { Router, Request, Response } from 'express';
    import { executeQuery } from './db';
    const authMiddleware = require('./middleware/auth');

    interface UserPayload<T> {
        user: T;
        tenantId: string;
    }

    class BaseController {
        constructor() {}
    }

    class DocumentController extends BaseController {
        async handleGet(req: Request, res: Response) {
            const docId = req?.params?.id;
            const query = `SELECT * FROM docs WHERE id = '${docId}'`;
            executeQuery(query);
        }
    }

    export const processOrder = async (orderId: string, callback: (err: any, data: any) => void) => {
        const url = req?.user?.endpoint;
        setTimeout(() => {
            callback(null, { status: 'processed' });
        }, 100);
    };

    const router = Router();
    router.get('/documents/:id', authMiddleware, DocumentController.prototype.handleGet);
    router.post('/eval', (req, res) => {
        eval(req.body.code);
    });

    export default router;
    """

    graph = SemanticProgramGraph()
    res = frontend.parse_file("controller.ts", sample_js, graph, Path("."))

    assert res.parsed_successfully is True
    assert res.nodes_created > 0

    # Verify extracted classes and inheritance
    classes = graph.find_nodes(kind=NodeKind.CLASS)
    class_names = [c.label for c in classes]
    assert "BaseController" in class_names
    assert "DocumentController" in class_names
    doc_cls = [c for c in classes if c.label == "DocumentController"][0]
    assert "BaseController" in doc_cls.properties.get("bases", [])

    # Verify extracted exports
    exports = graph.find_nodes(kind=NodeKind.MODULE)
    export_labels = [e.label for e in exports]
    assert any("export processOrder" in el for el in export_labels)
    assert any("export router" in el for el in export_labels)

    # Verify arrow functions
    funcs = graph.find_nodes(kind=NodeKind.FUNCTION)
    func_names = [f.label for f in funcs]
    assert "processOrder" in func_names

    # Verify Express routes and auth middleware
    routes = graph.find_nodes(kind=NodeKind.ROUTE)
    route_paths = [r.properties.get("route_path") for r in routes]
    assert "/documents/:id" in route_paths

    auth_nodes = graph.find_nodes(kind=NodeKind.AUTH_CONTROL)
    assert len(auth_nodes) >= 1
    assert any("authMiddleware" in a.label for a in auth_nodes)

    # Verify dangerous sinks: SQL and eval
    queries = graph.find_nodes(kind=NodeKind.QUERY)
    assert len(queries) >= 1

    eval_sinks = graph.find_nodes(kind=NodeKind.SENSITIVE_SINK)
    assert len(eval_sinks) >= 1

    # Verify coverage gaps are explicitly reported rather than silently ignored
    gaps = res.gaps
    assert any("TypeScript type definitions" in g for g in gaps)
    assert any("Optional chaining (?.)" in g for g in gaps)
    assert any("Callback/closure lexical environment" in g for g in gaps)
    assert any("eval()" in g for g in gaps)
