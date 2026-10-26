"""Order controller receiving search query."""

from services.order_service import search_orders


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


order_app = ControllerApp()


@order_app.route("/api/v1/orders/search")
def search_view(query: str):
    """Entry point passing query down through 3+ modules to DB."""
    return search_orders(query)
