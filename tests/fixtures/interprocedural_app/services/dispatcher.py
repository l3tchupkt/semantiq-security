"""Dynamic action dispatcher using runtime reflection."""


class DynamicActionDispatcher:
    def dispatch(self, action_name: str, payload: str):
        """Invoke handler dynamically via getattr, which cannot be resolved statically."""
        handler = getattr(self, f"handle_{action_name}", None)
        if callable(handler):
            return handler(payload)
        return None

    def handle_reset(self, payload: str):
        return f"reset: {payload}"
