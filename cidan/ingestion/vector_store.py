import json
from datetime import datetime, timezone

from langchain_chroma import Chroma
from langchain_community.embeddings import FastEmbedEmbeddings

from cidan.config import Settings, get_settings
from cidan.ingestion.chunking import split_documents
from cidan.ingestion.pdf_loader import load_source_pdfs

COLLECTION_NAME = "cidan_source_documents_fastembed"


def create_vector_store(settings: Settings | None = None) -> Chroma:
    active = settings or get_settings()
    embeddings = FastEmbedEmbeddings(model_name=active.embedding_model)
    return Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=embeddings,
        persist_directory=str(active.chroma_persist_directory),
    )


def ingest(settings: Settings | None = None) -> dict[str, object]:
    active = settings or get_settings()
    pages = load_source_pdfs(active)
    chunks = split_documents(pages)
    store = create_vector_store(active)
    ids = [chunk.metadata["chunk_id"] for chunk in chunks]
    for document_type in {page.metadata["document_type"] for page in pages}:
        previous = store.get(where={"document_type": document_type})
        previous_ids = previous.get("ids", [])
        if previous_ids:
            store.delete(ids=previous_ids)
    store.add_documents(chunks, ids=ids)
    manifest_path = active.chroma_persist_directory.parent / "ingestion_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_documents: dict[str, dict[str, object]] = {}
    for page in pages:
        filename = page.metadata["filename"]
        entry = manifest_documents.setdefault(filename, {
            "filename": filename,
            "document_id": page.metadata["document_id"],
            "pages": 0,
        })
        entry["pages"] = int(entry["pages"]) + 1
    manifest = {
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "embedding_provider": "fastembed_local",
        "embedding_model": active.embedding_model,
        "documents": list(manifest_documents.values()),
        "chunks": len(chunks),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "documents": sorted({page.metadata["filename"] for page in pages}),
        "pages": len(pages),
        "chunks": len(chunks),
        "index_directory": str(active.chroma_persist_directory),
        "ingested_at": manifest["ingested_at"],
    }
