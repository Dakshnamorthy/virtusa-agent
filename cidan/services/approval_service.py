from datetime import datetime, timezone

from cidan.models import ApprovalRecord
from cidan.workflow.persistence import audit, list_workflows, save_workflow


def approve_rule(rule_id: str, reviewer_id: str, note: str = "") -> dict:
    if not reviewer_id.strip():
        raise ValueError("Reviewer identifier is required.")
    for workflow in list_workflows():
        for rule in workflow.get("proposals", []):
            if rule.get("rule_id") != rule_id:
                continue
            if rule.get("status") != "validated":
                raise ValueError("Rule approval requires successful validation.")
            tests = workflow.get("tests", [])
            if not tests or any(test["failed"] or test["invalid"] for test in tests):
                raise ValueError("Rule approval requires executed, passing validation tests.")
            approval = ApprovalRecord(
                rule_id=rule_id,
                version=rule["version"],
                reviewer_id=reviewer_id,
                decision="approve",
                approved_at=datetime.now(timezone.utc),
                note=note,
            )
            rule["status"] = "approved_for_export"
            rule["approval"] = approval.model_dump(mode="json")
            save_workflow(workflow)
            audit("rule_approved_locally", {
                "workflow_id": workflow["workflow_id"], "rule_id": rule_id,
                "version": rule["version"], "reviewer_id": reviewer_id,
            })
            return rule
    raise FileNotFoundError(f"Rule not found: {rule_id}")


def export_preview(rule_id: str) -> dict:
    for workflow in list_workflows():
        for rule in workflow.get("proposals", []):
            if rule.get("rule_id") != rule_id:
                continue
            if rule.get("status") != "approved_for_export" or not rule.get("approval"):
                raise PermissionError("Explicit local human approval is required before export.")
            tests = workflow.get("tests", [])
            if not tests or any(test["failed"] or test["invalid"] for test in tests):
                raise ValueError("Export requires completed validation with no failed or invalid tests.")
            package = {
                "environment": "SIMULATION_ONLY",
                "rule": rule,
                "validation": tests,
                "source_evidence": rule["supporting_citations"],
                "rollback_notes": rule["rollback_considerations"],
                "disclaimer": "Local preview only. Not legal approval or production deployment.",
            }
            audit("rule_export_previewed", {
                "workflow_id": workflow["workflow_id"], "rule_id": rule_id,
            })
            return package
    raise FileNotFoundError(f"Rule not found: {rule_id}")
