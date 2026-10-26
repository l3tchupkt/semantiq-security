"""Order manager layer dispatching to DAO layer."""

from dao.order_dao import fetch_orders_by_title


def dispatch_order_search(query: str):
    """Pass query to DAO layer."""
    return fetch_orders_by_title(query)
