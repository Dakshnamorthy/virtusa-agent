from fastapi.testclient import TestClient

from cidan.api import app

client = TestClient(app)


def test_health_does_not_expose_api_key():
    response = client.get("/health")
    assert response.status_code == 200
    assert "test-secret" not in response.text
    assert "api_key" not in response.text.casefold()
    assert response.json()["llm_provider"] == "groq"
    assert response.json()["embedding_provider"] == "fastembed_local"


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


def test_approval_request_validation():
    response = client.post("/rules/not-found/approve", json={"reviewer_id": ""})
    assert response.status_code == 422
