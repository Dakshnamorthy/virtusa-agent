import json
import logging

from cidan.config import get_settings
from cidan.orchestrator import run_workflow

if __name__ == "__main__":
    logging.basicConfig(level=get_settings().log_level)
    result = run_workflow()
    print(json.dumps({
        "workflow_id": result.get("workflow_id"),
        "stage": result.get("stage"),
        "error": result.get("error"),
        "report": result.get("report"),
        "report_json_path": result.get("report_json_path"),
        "report_markdown_path": result.get("report_markdown_path"),
        "proposals": result.get("proposals", []),
    }, indent=2))
