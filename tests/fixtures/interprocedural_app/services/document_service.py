"""Document service retrieving document from DAO."""

from dao.document_dao import query_document_by_id


def fetch_document(doc_id: str):
    """Fetch document by doc_id without session tenant validation."""
    return query_document_by_id(doc_id)
