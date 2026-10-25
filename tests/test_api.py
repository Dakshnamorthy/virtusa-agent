import pymupdf
import pytest
from fastapi.testclient import TestClient

from cidan.api import app


@pytest.fixture(autouse=True)
def configure_test_access_token(monkeypatch):
    monkeypatch.setenv("CIDAN_ACCESS_TOKEN", "test-access-token")


client = TestClient(app, headers={"Authorization": "Bearer test-access-token"})


def make_pdf(text):
    document = pymupdf.open()
    page = document.new_page()
    page.insert_text((72, 72), text)
    content = document.tobytes()
    document.close()
    return content


def test_health_does_not_expose_api_key():
    response = client.get("/health")
    assert response.status_code == 200
    assert "test-secret" not in response.text
    assert "api_key" not in response.text.casefold()
    assert "test-access-token" not in response.text
    assert response.json()["llm_provider"] == "groq"
    assert response.json()["embedding_provider"] == "fastembed_local"
    assert response.json()["llm_max_output_tokens"] == 400


def test_groq_configuration_does_not_use_openai_key(monkeypatch):
    from cidan.config import get_settings

    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "unused-openai-test-key")
    assert get_settings().llm_configured is False
    monkeypatch.setenv("GROQ_API_KEY", "test-groq-key")
    assert get_settings().llm_configured is True


def test_documents_finds_both_demo_pdfs():
    response = client.get("/documents")
    assert response.status_code == 200
    data = response.json()
    assert data["expected_count"] == 2
    assert data["found_count"] == 2


def test_api_operations_require_bearer_token():
    response = TestClient(app).get("/documents")
    assert response.status_code == 401


def test_api_operations_fail_closed_without_configured_token(monkeypatch):
    monkeypatch.delenv("CIDAN_ACCESS_TOKEN")
    response = client.get("/documents")
    assert response.status_code == 503


def test_upload_replaces_source_pdfs_with_classified_pair(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_PDF_DIRECTORY", str(tmp_path / "source_pdfs"))
    response = client.post(
        "/documents/upload",
        files={
            "handbook": (
                "sample_policy_handbook.pdf",
                make_pdf("Policy handbook sample text."),
                "application/pdf",
            ),
            "circular": (
                "sample_circular.pdf",
                make_pdf("Circular sample text."),
                "application/pdf",
            ),
        },
    )
    assert response.status_code == 201
    assert response.json()["message"].startswith("Both source PDFs were stored")
    documents = response.json()["documents"]
    assert [item["document_type"] for item in documents] == [
        "policy_handbook", "circular"
    ]
    assert len(list((tmp_path / "source_pdfs").glob("*.pdf"))) == 2


def test_upload_rejects_files_with_wrong_document_names(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_PDF_DIRECTORY", str(tmp_path / "source_pdfs"))
    response = client.post(
        "/documents/upload",
        files={
            "handbook": ("sample_circular.pdf", make_pdf("Circular text."), "application/pdf"),
            "circular": ("another_circular.pdf", make_pdf("Circular text."), "application/pdf"),
        },
    )
    assert response.status_code == 400
    assert not (tmp_path / "source_pdfs").exists()


def test_upload_rejects_non_pdf_content_without_replacing_source(tmp_path, monkeypatch):
    source_directory = tmp_path / "source_pdfs"
    source_directory.mkdir()
    original = source_directory / "existing_policy_handbook.pdf"
    original.write_bytes(b"existing")
    monkeypatch.setenv("SOURCE_PDF_DIRECTORY", str(source_directory))
    response = client.post(
        "/documents/upload",
        files={
            "handbook": ("new_policy_handbook.pdf", b"not a PDF", "application/pdf"),
            "circular": ("new_circular.pdf", make_pdf("Circular sample text."), "application/pdf"),
        },
    )
    assert response.status_code == 400
    assert original.read_bytes() == b"existing"


def test_approval_request_validation():
    response = client.post("/rules/not-found/approve", json={"reviewer_id": ""})
    assert response.status_code == 422
