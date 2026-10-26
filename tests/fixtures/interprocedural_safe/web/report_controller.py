"""Safe report controller."""

from services.report_service import generate_report


class ControllerApp:
    def route(self, path: str, methods: list[str] | None = None):
        def decorator(f):
            return f
        return decorator


report_app = ControllerApp()


@report_app.route("/api/v1/reports/export")
def report_export_view(report_id: str, format_type: str = "json"):
    return generate_report(report_id, format_type)
