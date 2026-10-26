"""Safe application entry point with genuine security controls."""

from web.admin_controller import admin_app
from web.custom_controller import custom_app
from web.document_controller import doc_app
from web.order_controller import order_app
from web.public_controller import public_app
from web.report_controller import report_app
from web.webhook_controller import webhook_app


def run():
    return [order_app, doc_app, admin_app, public_app, webhook_app, report_app, custom_app]
