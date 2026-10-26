"""Safe webhook service validating target URL before request."""

import requests
from helpers.network_helper import format_webhook_endpoint, validate_url


def dispatch_notification(target_url: str):
    validated = validate_url(target_url)
    endpoint = format_webhook_endpoint(validated)
    resp = requests.get(endpoint)
    return resp.status_code
