from pathlib import Path
from typing import Any

from cidan.agents.reporting import save
from cidan.services.workflow_service import execute_workflow


def run_workflow(output_dir: str | Path = "outputs") -> dict[str, Any]:
    """Run the real PDF/LLM workflow; never falls back to mock data."""
    result = execute_workflow()
    if result.get("report"):
        json_path, markdown_path = save(result["report"], output_dir)
        result["report_json_path"] = str(json_path)
        result["report_markdown_path"] = str(markdown_path)
    return result
