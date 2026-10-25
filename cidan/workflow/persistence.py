import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cidan.config import ROOT

logger = logging.getLogger(__name__)
WORKFLOWS_DIR = ROOT / "outputs" / "workflows"
AUDIT_PATH = ROOT / "outputs" / "audit.jsonl"


def workflow_path(workflow_id: str) -> Path:
    if not workflow_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in workflow_id):
        raise ValueError("Invalid workflow ID.")
    return WORKFLOWS_DIR / f"{workflow_id}.json"


def save_workflow(state: dict[str, Any]) -> Path:
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    path = workflow_path(state["workflow_id"])
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    temporary.replace(path)
    return path


def load_workflow(workflow_id: str) -> dict[str, Any]:
    path = workflow_path(workflow_id)
    if not path.is_file():
        raise FileNotFoundError(f"Workflow not found: {workflow_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_workflows() -> list[dict[str, Any]]:
    if not WORKFLOWS_DIR.is_dir():
        return []
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(WORKFLOWS_DIR.glob("*.json"))
    ]


def audit(event: str, details: dict[str, Any]) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    item = {
        "event_id": str(uuid4()),
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    with AUDIT_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(item, default=str) + "\n")
    logger.info("Audit event recorded: %s", event)
