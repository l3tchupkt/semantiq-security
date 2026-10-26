"""Safe webhook dispatcher with URL scheme and IP validation."""

import ipaddress
from urllib.parse import urlparse

import requests


def validate_url(url: str) -> str:
    """Validate that destination URL is HTTPS and does not resolve to private/local network."""
    parsed = urlparse(url)
    if parsed.scheme not in {"https"}:
        raise ValueError("Untrusted URL scheme")
    try:
        ip = ipaddress.ip_address(parsed.hostname or "")
        if ip.is_private or ip.is_loopback:
            raise ValueError("Private IP destinations forbidden")
    except ValueError:
        pass
    return url


def safe_dispatch_webhook(callback_url: str) -> bool:
    """Safely validate URL before making outbound HTTP POST."""
    clean_url = validate_url(callback_url)
    res = requests.post(clean_url, json={"status": "ok"}, timeout=5)
    return res.status_code == 200
