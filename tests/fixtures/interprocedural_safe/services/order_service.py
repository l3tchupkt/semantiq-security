"""Safe order service."""

from managers.order_manager import dispatch_order_search


def search_orders(query: str):
    return dispatch_order_search(query)
