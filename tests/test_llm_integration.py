import os

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("CIDAN_RUN_LLM_INTEGRATION") != "1",
    reason="Set CIDAN_RUN_LLM_INTEGRATION=1 to call configured LLM and embeddings.",
)


def test_real_pdf_llm_workflow():
    from cidan.services.workflow_service import execute_workflow

    result = execute_workflow()
    assert result.get("error") is None
    assert result.get("report")
    assert result["report"]["source_status"] == "synthetic_demo_source"
