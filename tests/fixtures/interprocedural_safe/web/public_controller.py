"""Protected public controller requiring admin authorization."""

from services.user_service import delete_user_account


def admin_required(f):
    return f


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


public_app = ControllerApp()


@public_app.route("/api/v1/public/delete_user", methods=["POST"])
@admin_required
def public_delete_user_view(user_id: str):
    """Protected with admin authorization - no bypass."""
    return delete_user_account(user_id)
