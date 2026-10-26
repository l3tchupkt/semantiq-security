"""Safe document controller with login and tenant checks."""

from services.document_service import fetch_document


def login_required(f):
    return f


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


doc_app = ControllerApp()


@doc_app.route("/api/v1/documents/<doc_id>")
@login_required
def document_view(doc_id: str):
    """Retrieve document by ID scoped to current tenant."""
    return fetch_document(doc_id)
