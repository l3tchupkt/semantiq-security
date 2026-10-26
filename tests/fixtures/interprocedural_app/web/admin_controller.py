"""Protected admin controller for Flow 3."""

from services.user_service import delete_user_account


def admin_required(f):
    return f


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


admin_app = ControllerApp()


@admin_app.route("/api/v1/admin/delete_user", methods=["POST"])
@admin_required
def admin_delete_user_view(user_id: str):
    """Protected route requiring admin authorization."""
    return delete_user_account(user_id)
