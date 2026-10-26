"""Multi-tenant SaaS application entry point for Semantiq benchmark."""

from services.file_service import export_file
from services.payment_service import fulfill_order
from services.role_service import assign_role
from services.tenant_service import get_tenant_document
from services.user_service import get_user_profile
from services.webhook_service import dispatch_webhook


class FlaskApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


app = FlaskApp()


@app.route("/api/v1/tenant/documents/<doc_id>")
def document_view(doc_id: str):
    return get_tenant_document(doc_id)


@app.route("/api/v1/admin/assign_role", methods=["POST"])
def role_view(user_id: str, new_role: str):
    return assign_role(user_id, new_role)


@app.route("/api/v1/webhooks/dispatch", methods=["POST"])
def webhook_view(callback_url: str):
    return dispatch_webhook(callback_url)


@app.route("/api/v1/files/export")
def file_export_view(file_name: str):
    return export_file(file_name)


@app.route("/api/v1/orders/fulfill", methods=["POST"])
def order_fulfill_view(order_id: str):
    return fulfill_order(order_id)


@app.route("/api/v1/users/profile/<user_id>")
def profile_view(user_id: str):
    return get_user_profile(user_id)
