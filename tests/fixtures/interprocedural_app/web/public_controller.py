"""Unprotected public controller exposing sensitive service without auth."""

from services.user_service import delete_user_account


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


public_app = ControllerApp()


@public_app.route("/api/v1/public/delete_user", methods=["POST"])
def public_delete_user_view(user_id: str):
    """Unprotected bypass route reaching the same sensitive deletion service."""
    return delete_user_account(user_id)
