"""Order service layer passing search query to manager."""

from managers.order_manager import dispatch_order_search


def search_orders(query: str):
    """Pass query to manager layer."""
    return dispatch_order_search(query)
