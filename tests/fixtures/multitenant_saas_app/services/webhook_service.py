"""Outgoing webhook notification dispatcher service."""

import requests


def _send_http_payload(endpoint_url: str, payload: dict) -> int:
    """Internal helper transmitting HTTP POST request."""
    # VULNERABILITY: SQ-PY-004 SSRF via unvalidated HTTP destination
    res = requests.post(endpoint_url, json=payload, timeout=5)
    return res.status_code


def dispatch_webhook(callback_url: str) -> bool:
    """Public service entry point receiving callback URL from client."""
    event_payload = {"event": "order_created", "status": "pending"}
    code = _send_http_payload(callback_url, event_payload)
    return code == 200
