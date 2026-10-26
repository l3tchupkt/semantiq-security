"""Safe static action dispatcher using explicit handler map."""


class StaticActionDispatcher:
    def __init__(self):
        self.handlers = {
            "reset": self.handle_reset,
        }

    def dispatch(self, action_name: str, payload: str):
        handler = self.handlers.get(action_name)
        if handler:
            return handler(payload)
        return None

    def handle_reset(self, payload: str):
        return f"safe reset: {payload}"
