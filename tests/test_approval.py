import json

import pytest

from cidan.services.approval_service import approve_rule, export_preview
from cidan.workflow import persistence


def proposal(status):
    return {
        "rule_id": "draft-1", "version": 1, "status": status,
        "supporting_citations": [{"filename": "circular.pdf", "page": 1}],
        "rollback_considerations": "Restore prior local config.",
    }


def write_workflow(directory, status):
    directory.mkdir(parents=True, exist_ok=True)
    data = {
        "workflow_id": "workflow-1", "proposals": [proposal(status)],
        "tests": [{"failed": 0, "invalid": 0, "total": 1, "passed": 1}],
    }
    (directory / "workflow-1.json").write_text(json.dumps(data), encoding="utf-8")


def test_approval_requires_validation_and_reviewer(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "WORKFLOWS_DIR", tmp_path / "workflows")
    monkeypatch.setattr(persistence, "AUDIT_PATH", tmp_path / "audit.jsonl")
    write_workflow(tmp_path / "workflows", "draft")
    with pytest.raises(ValueError, match="successful validation"):
        approve_rule("draft-1", "reviewer-7")


def test_approval_is_audited_and_export_requires_it(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "WORKFLOWS_DIR", tmp_path / "workflows")
    monkeypatch.setattr(persistence, "AUDIT_PATH", tmp_path / "audit.jsonl")
    write_workflow(tmp_path / "workflows", "validated")
    with pytest.raises(PermissionError):
        export_preview("draft-1")
    approved = approve_rule("draft-1", "reviewer-7", "Reviewed locally.")
    assert approved["status"] == "approved_for_export"
    assert approved["approval"]["reviewer_id"] == "reviewer-7"
    package = export_preview("draft-1")
    assert package["environment"] == "SIMULATION_ONLY"
    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "rule_approved_locally" in audit
    assert "rule_export_previewed" in audit
