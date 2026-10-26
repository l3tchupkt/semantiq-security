"""Webhook service making external HTTP request via helper."""

import requests
from helpers.network_helper import format_webhook_endpoint


def dispatch_notification(target_url: str):
    """Pass target_url through helper before SSRF-sensitive HTTP request."""
    endpoint = format_webhook_endpoint(target_url)
    resp = requests.get(endpoint)
    return resp.status_code
