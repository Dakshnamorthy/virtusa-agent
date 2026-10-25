from typing import Any, TypedDict

from langchain_core.documents import Document


class WorkflowState(TypedDict, total=False):
    workflow_id: str
    stage: str
    error: str | None
    failed_stage: str
    blocked_stages: list[str]
    documents: list[Document]
    obligations: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    proposals: list[dict[str, Any]]
    tests: list[dict[str, Any]]
    report: dict[str, Any]
