from pathlib import Path
from typing import Any

from cidan.agents.reporting import save
from cidan.config import ROOT, get_settings
from cidan.services.workflow_service import execute_workflow


def run_workflow(output_dir: str | Path | None = None) -> dict[str, Any]:
    """Run the real PDF/LLM workflow; never falls back to mock data."""
    result = execute_workflow()
    if result.get("report"):
        target_dir = output_dir or get_settings().outputs_directory
        json_path, markdown_path = save(result["report"], target_dir)
        result["report_json_path"] = (
            str(json_path.relative_to(ROOT)) if json_path.is_relative_to(ROOT) else str(json_path)
        )
        result["report_markdown_path"] = (
            str(markdown_path.relative_to(ROOT)) if markdown_path.is_relative_to(ROOT) else str(markdown_path)
        )
    return result
