"""Safe report service sanitizing report_id across all execution branches."""

from dao.report_dao import run_report_query


def generate_report(report_id: str, format_type: str):
    # Both branches sanitize through int conversion
    if format_type == "csv":
        safe_id = int(report_id)
        return run_report_query(safe_id)
    else:
        safe_id = int(report_id)
        return run_report_query(safe_id)
