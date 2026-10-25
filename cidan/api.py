import logging
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from cidan.config import ConfigurationError, get_settings
from cidan.agents.reporting import render_markdown
from cidan.ingestion.pdf_loader import classify_document, find_pdfs, ingestion_status
from cidan.ingestion.vector_store import ingest
from cidan.services.approval_service import approve_rule, export_preview
from cidan.services.workflow_service import execute_workflow
from cidan.workflow.persistence import load_workflow, list_workflows

logger = logging.getLogger(__name__)
app = FastAPI(
    title="CIDAN - Regulatory Circular to Live Rule Engine",
    version="0.2.0",
    description="Local synthetic compliance analysis prototype; no production deployment.",
)


class ApprovalRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=128)
    note: str = Field(default="", max_length=2000)


@app.get("/health")
def health() -> dict[str, Any]:
    settings = get_settings()
    return {
        "status": "ready" if settings.llm_configured else "needs_configuration",
        "llm_configured": settings.llm_configured,
        "llm_provider": "groq",
        "llm_model": settings.llm_model,
        "embedding_model": settings.embedding_model,
        "embedding_provider": "fastembed_local",
        "source_directory": str(settings.source_pdf_directory),
        "message": None if settings.llm_configured else "Add a Groq API credential to the local .env file.",
    }


@app.get("/documents")
def documents() -> dict[str, Any]:
    settings = get_settings()
    pdfs = find_pdfs(settings)
    statuses = ingestion_status(settings)
    return {
        "expected_count": 2,
        "found_count": len(pdfs),
        "source_directory": str(settings.source_pdf_directory),
        "documents": [
            {
                "filename": path.name,
                "document_type": classify_document(path),
                "size_bytes": path.stat().st_size,
                "ingestion_status": statuses.get(path.name, "not_indexed"),
            }
            for path in pdfs
        ],
        "ready": len(pdfs) == 2,
    }


@app.post("/ingest")
def ingest_documents() -> dict[str, Any]:
    try:
        return ingest()
    except ConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        if isinstance(exc, ConfigurationError):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        logger.exception("Document ingestion failed")
        raise HTTPException(status_code=502, detail="Ingestion failed; check local logs.") from exc


@app.post("/workflows/analyze", status_code=201)
def analyze() -> dict[str, Any]:
    try:
        result = execute_workflow()
    except Exception as exc:
        logger.exception("Workflow execution failed unexpectedly")
        raise HTTPException(status_code=500, detail="Workflow failed; check local logs.") from exc
    if result.get("error"):
        status = 503 if "GROQ_API_KEY" in result["error"] else 502
        raise HTTPException(
            status_code=status,
            detail={"message": result["error"], "workflow_id": result["workflow_id"]},
        )
    return result


@app.get("/workflows")
def workflows() -> list[dict[str, Any]]:
    return [
        {
            "workflow_id": workflow["workflow_id"],
            "stage": workflow.get("stage"),
            "error": workflow.get("error"),
        }
        for workflow in list_workflows()
    ]


@app.get("/workflows/{workflow_id}")
def workflow_result(workflow_id: str) -> dict[str, Any]:
    try:
        return load_workflow(workflow_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/workflows/{workflow_id}/report")
def workflow_report(workflow_id: str) -> dict[str, Any]:
    result = workflow_result(workflow_id)
    if "report" not in result:
        raise HTTPException(status_code=409, detail="Report is unavailable because the workflow did not complete.")
    return result["report"]


@app.get("/workflows/{workflow_id}/report/markdown")
def workflow_report_markdown(workflow_id: str) -> PlainTextResponse:
    report = workflow_report(workflow_id)
    return PlainTextResponse(render_markdown(report), media_type="text/markdown")


@app.get("/rules")
def rules() -> list[dict[str, Any]]:
    return [
        {"workflow_id": workflow["workflow_id"], **proposal}
        for workflow in list_workflows()
        for proposal in workflow.get("proposals", [])
    ]


@app.get("/rules/{rule_id}")
def get_rule(rule_id: str) -> dict[str, Any]:
    for workflow in list_workflows():
        for proposal in workflow.get("proposals", []):
            if proposal.get("rule_id") == rule_id:
                return {"workflow_id": workflow["workflow_id"], **proposal}
    raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")


@app.post("/rules/{rule_id}/approve")
def approve(rule_id: str, request: ApprovalRequest) -> dict[str, Any]:
    try:
        return approve_rule(rule_id, request.reviewer_id, request.note)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/rules/{rule_id}/export-preview")
def preview_export(rule_id: str) -> dict[str, Any]:
    try:
        return export_preview(rule_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
