import hashlib

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter


def split_documents(
    pages: list[Document], chunk_size: int = 1000, chunk_overlap: int = 150
) -> list[Document]:
    if chunk_size <= 0 or chunk_overlap < 0 or chunk_overlap >= chunk_size:
        raise ValueError("Require chunk_size > chunk_overlap >= 0.")
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        add_start_index=True,
    )
    chunks: list[Document] = []
    for page in pages:
        for piece in splitter.split_documents([page]):
            metadata = dict(piece.metadata)
            chunk_id = hashlib.sha256(
                f"{metadata['document_id']}:{metadata['page']}:"
                f"{metadata.get('start_index', 0)}:{piece.page_content}".encode("utf-8")
            ).hexdigest()
            metadata["chunk_id"] = chunk_id
            piece.metadata = metadata
            chunks.append(piece)
    return chunks
