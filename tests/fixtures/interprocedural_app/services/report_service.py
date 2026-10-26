"""Report service with sanitized and unsanitized branches reaching the same sink."""

from dao.report_dao import run_report_query


def generate_report(report_id: str, format_type: str):
    """Sanitized in csv branch, unsanitized in default branch."""
    if format_type == "csv":
        safe_id = int(report_id)
        return run_report_query(safe_id)
    else:
        raw_id = report_id
        return run_report_query(raw_id)
