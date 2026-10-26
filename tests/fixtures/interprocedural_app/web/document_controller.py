"""Document controller accessing tenant document by ID."""

from services.document_service import fetch_document


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


doc_app = ControllerApp()


@doc_app.route("/api/v1/documents/<doc_id>")
def document_view(doc_id: str):
    """Retrieve document by ID without tenant scoping."""
    return fetch_document(doc_id)
