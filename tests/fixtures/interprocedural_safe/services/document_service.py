"""Safe document service passing to DAO."""

from dao.document_dao import query_document_by_id


def fetch_document(doc_id: str):
    return query_document_by_id(doc_id)
