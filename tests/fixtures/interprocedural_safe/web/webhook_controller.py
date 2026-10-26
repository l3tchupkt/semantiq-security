"""Safe webhook controller."""

from services.webhook_service import dispatch_notification


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


webhook_app = ControllerApp()


@webhook_app.route("/api/v1/webhook/trigger", methods=["POST"])
def trigger_view(target_url: str):
    return dispatch_notification(target_url)
