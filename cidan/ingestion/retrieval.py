from langchain_core.documents import Document

from cidan.ingestion.vector_store import create_vector_store
from cidan.models import Citation


def retrieve(query: str, document_type: str, k: int = 6) -> list[Document]:
    store = create_vector_store()
    return store.similarity_search(
        query,
        k=k,
        filter={"document_type": document_type},
    )


def citation_for(document: Document) -> Citation:
    metadata = document.metadata
    return Citation(
        document_id=metadata["document_id"],
        filename=metadata["filename"],
        document_type=metadata["document_type"],
        page=int(metadata["page"]),
        excerpt=document.page_content[:600],
        chunk_id=metadata["chunk_id"],
    )
