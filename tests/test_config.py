import pytest

from cidan.config import get_settings


def test_llm_max_output_tokens_defaults_to_reduced_limit(monkeypatch):
    monkeypatch.delenv("LLM_MAX_OUTPUT_TOKENS", raising=False)

    assert get_settings().llm_max_output_tokens == 400


def test_llm_max_output_tokens_can_be_configured(monkeypatch):
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", "300")

    assert get_settings().llm_max_output_tokens == 300


@pytest.mark.parametrize("value", ["0", "-1", "invalid"])
def test_llm_max_output_tokens_rejects_invalid_values(monkeypatch, value):
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", value)

    with pytest.raises(ValueError, match="positive integer"):
        get_settings()
