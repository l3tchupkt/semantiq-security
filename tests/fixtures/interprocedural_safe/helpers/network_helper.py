"""Safe network helper validating target URLs."""


def validate_url(url: str) -> str:
    """Validate target URL against allowed domain whitelist."""
    if url.startswith("https://trusted.corp.internal/"):
        return url
    raise ValueError("Untrusted URL target")


def format_webhook_endpoint(url: str) -> str:
    return validate_url(url.strip())
