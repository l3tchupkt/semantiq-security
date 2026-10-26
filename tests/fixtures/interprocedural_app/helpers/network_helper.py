"""Network helper utility function."""


def format_webhook_endpoint(url: str) -> str:
    """Helper normalizing webhook URL without SSRF validation."""
    return url.strip()
