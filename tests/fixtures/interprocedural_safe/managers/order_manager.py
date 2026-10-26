"""Safe order manager."""

from dao.order_dao import fetch_orders_by_title


def dispatch_order_search(query: str):
    return fetch_orders_by_title(query)
