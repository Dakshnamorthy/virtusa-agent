from uuid import uuid4

from cidan.agents.reporting import save
from cidan.config import ROOT, get_settings
from cidan.workflow.graph import run_graph
from cidan.workflow.persistence import audit, save_workflow


def execute_workflow() -> dict:
    workflow_id = str(uuid4())
    result = run_graph(workflow_id)
    result.pop("documents", None)
    result["workflow_id"] = workflow_id
    if result.get("report"):
        report_dir = get_settings().outputs_directory / "reports" / workflow_id
        json_path, markdown_path = save(result["report"], report_dir)
        result["report_files"] = {
            "json": str(json_path.relative_to(ROOT)) if json_path.is_relative_to(ROOT) else str(json_path),
            "markdown": str(markdown_path.relative_to(ROOT)) if markdown_path.is_relative_to(ROOT) else str(markdown_path),
        }
    save_workflow(result)
    audit("workflow_completed" if not result.get("error") else "workflow_failed", {
        "workflow_id": workflow_id, "stage": result.get("stage"),
    })
    return result
