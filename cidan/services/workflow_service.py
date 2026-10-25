from uuid import uuid4

from cidan.agents.reporting import save
from cidan.config import ROOT
from cidan.workflow.graph import run_graph
from cidan.workflow.persistence import audit, save_workflow


def execute_workflow() -> dict:
    workflow_id = str(uuid4())
    result = run_graph(workflow_id)
    result.pop("documents", None)
    result["workflow_id"] = workflow_id
    if result.get("report"):
        report_dir = ROOT / "outputs" / "reports" / workflow_id
        json_path, markdown_path = save(result["report"], report_dir)
        result["report_files"] = {
            "json": str(json_path.relative_to(ROOT)),
            "markdown": str(markdown_path.relative_to(ROOT)),
        }
    save_workflow(result)
    audit("workflow_completed" if not result.get("error") else "workflow_failed", {
        "workflow_id": workflow_id, "stage": result.get("stage"),
    })
    return result
