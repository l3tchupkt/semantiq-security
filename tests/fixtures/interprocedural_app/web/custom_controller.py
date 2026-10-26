"""Custom controller invoking method resolved through inheritance."""

from repositories.custom_repo import CustomRepository


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


custom_app = ControllerApp()


@custom_app.route("/api/v1/custom/filter")
def filter_view(tag: str):
    """Entry point invoking repository with inherited method."""
    repo = CustomRepository()
    return repo.find_by_filter(tag)
