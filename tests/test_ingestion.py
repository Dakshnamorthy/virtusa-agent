from langchain_core.documents import Document

from cidan.config import get_settings
from cidan.ingestion import vector_store
from cidan.ingestion.chunking import split_documents
from cidan.ingestion.pdf_loader import classify_document, find_pdfs, load_pdf
from cidan.ingestion.retrieval import citation_for, retrieve


def test_discovers_and_parses_two_source_pdfs():
    paths = find_pdfs()
    assert len(paths) == 2
    assert {classify_document(path) for path in paths} == {
        "policy_handbook", "circular"
    }
    pages = [page for path in paths for page in load_pdf(path)]
    assert pages
    assert all(page.metadata["page"] >= 1 for page in pages)
    assert all(page.metadata["filename"] for page in pages)
    assert all(page.metadata["document_id"] for page in pages)


def test_chunks_preserve_page_citation_and_stable_ids():
    docs = [
        Document(
            page_content=("Sample source passage. " * 100),
            metadata={
                "document_id": "abc", "filename": "sample-circular.pdf",
                "document_type": "circular", "page": 3, "ingested_at": "now",
            },
        )
    ]
    first = split_documents(docs, chunk_size=180, chunk_overlap=20)
    second = split_documents(docs, chunk_size=180, chunk_overlap=20)
    assert len(first) > 1
    assert [item.metadata["chunk_id"] for item in first] == [
        item.metadata["chunk_id"] for item in second
    ]
    citation = citation_for(first[0])
    assert citation.page == 3
    assert citation.filename == "sample-circular.pdf"
    assert citation.excerpt in first[0].page_content


def test_ingestion_replaces_previous_chunks_without_network(monkeypatch):
    class FakeStore:
        def __init__(self):
            self.deleted: list[str] = []
            self.added: list[str] = []

        def get(self, where):
            return {"ids": ["old-" + where["document_type"]]}

        def delete(self, ids):
            self.deleted.extend(ids)

        def add_documents(self, _docs, ids):
            assert _docs
            self.added.extend(ids)

    store = FakeStore()
    def fake_create_vector_store(_settings):
        assert _settings is not None
        return store

    monkeypatch.setattr(vector_store, "create_vector_store", fake_create_vector_store)
    result = vector_store.ingest(get_settings())
    assert result["chunks"] == len(store.added) > 0
    assert len(store.deleted) == 2
    assert len(store.added) == len(set(store.added))


def test_retrieval_returns_citable_documents(monkeypatch):
    expected = Document(
        page_content="The loan reviewer shall document the decision.",
        metadata={
            "document_id": "doc-id", "filename": "policy.pdf",
            "document_type": "policy_handbook", "page": 2,
            "chunk_id": "chunk-id",
        },
    )

    class FakeStore:
        def similarity_search(self, query, *, k, filter):
            assert query == "loan reviewer"
            assert k == 6
            assert filter == {"document_type": "policy_handbook"}
            return [expected]

    monkeypatch.setattr("cidan.ingestion.retrieval.create_vector_store", FakeStore)
    actual = retrieve("loan reviewer", "policy_handbook")
    assert actual == [expected]
    assert citation_for(actual[0]).chunk_id == "chunk-id"
