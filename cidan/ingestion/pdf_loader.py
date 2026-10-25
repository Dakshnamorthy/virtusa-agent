import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pymupdf
from langchain_core.documents import Document

from cidan.config import ROOT, Settings, get_settings

logger = logging.getLogger(__name__)
MAX_PDF_COUNT = 2


def find_pdfs(settings: Settings | None = None) -> list[Path]:
    active = settings or get_settings()
    candidates = [active.source_pdf_directory, ROOT / "data", ROOT / "cidan" / "data", ROOT]
    for directory in candidates:
        if directory.is_dir():
            found = {str(path.resolve()).casefold(): path.resolve() for path in directory.glob("*.pdf")}
            if found:
                return sorted(found.values(), key=lambda path: path.name.casefold())
    return []


def classify_document(path: Path) -> str:
    name = path.name.casefold()
    if any(token in name for token in ("policy", "handbook", "rules")):
        return "policy_handbook"
    if any(token in name for token in ("circular", "regulatory", "rbi")):
        return "circular"
    return "unknown"


def load_pdf(path: Path, max_bytes: int = 25 * 1024 * 1024) -> list[Document]:
    if path.suffix.casefold() != ".pdf":
        raise ValueError(f"Unsupported source file type: {path.name}")
    if not path.is_file():
        raise FileNotFoundError(f"PDF does not exist: {path}")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"PDF exceeds the configured size limit: {path.name}")
    document_id = hashlib.sha256(path.read_bytes()).hexdigest()
    document_type = classify_document(path)
    ingested_at = datetime.now(timezone.utc).isoformat()
    pages: list[Document] = []
    try:
        with pymupdf.open(path) as pdf:
            for page_index, page in enumerate(pdf, start=1):
                text = page.get_text("text").strip()
                if not text:
                    logger.warning("No extractable text in %s page %s", path.name, page_index)
                    continue
                pages.append(Document(
                    page_content=text,
                    metadata={
                        "document_id": document_id,
                        "filename": path.name,
                        "document_type": document_type,
                        "page": page_index,
                        "ingested_at": ingested_at,
                    },
                ))
    except (pymupdf.FileDataError, RuntimeError) as exc:
        raise ValueError(f"Could not parse PDF {path.name}: {exc}") from exc
    if not pages:
        raise ValueError(f"PDF contains no extractable text: {path.name}")
    return pages


def load_source_pdfs(settings: Settings | None = None) -> list[Document]:
    active = settings or get_settings()
    pdfs = find_pdfs(active)
    if len(pdfs) != MAX_PDF_COUNT:
        raise FileNotFoundError(
            f"Expected exactly two source PDFs but discovered {len(pdfs)}. "
            f"Place the synthetic handbook and circular in "
            f"{active.source_pdf_directory} (or remove unrelated PDFs from the "
            "project data directories)."
        )
    documents: list[Document] = []
    types = {classify_document(path) for path in pdfs}
    if types != {"policy_handbook", "circular"}:
        raise ValueError(
            "Could not identify one handbook and one circular from filenames. "
            "Use filenames containing 'policy'/'handbook' and 'circular'/'rbi'."
        )
    for path in pdfs:
        documents.extend(load_pdf(path, active.max_pdf_bytes))
    return documents


def ingestion_status(settings: Settings | None = None) -> dict[str, str]:
    active = settings or get_settings()
    manifest_path = active.chroma_persist_directory.parent / "ingestion_manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception("Could not read local ingestion manifest")
        return {}
    indexed = {
        item["filename"]: item for item in manifest.get("documents", [])
    }
    status: dict[str, str] = {}
    for path in find_pdfs(active):
        manifest_item = indexed.get(path.name)
        if manifest_item is None:
            status[path.name] = "not_indexed"
        elif (
            hashlib.sha256(path.read_bytes()).hexdigest() != manifest_item["document_id"]
            or manifest.get("embedding_model") != active.embedding_model
        ):
            status[path.name] = "stale"
        else:
            status[path.name] = "indexed"
    return status
