import hmac
import logging
import tempfile
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from cidan.config import ConfigurationError, get_settings
from cidan.agents.reporting import render_markdown
from cidan.ingestion.pdf_loader import classify_document, find_pdfs, ingestion_status, load_pdf
from cidan.ingestion.vector_store import ingest
from cidan.services.approval_service import approve_rule, export_preview
from cidan.services.workflow_service import execute_workflow
from cidan.workflow.persistence import load_workflow, list_workflows

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)
app = FastAPI(
    title="CIDAN - Regulatory Circular to Live Rule Engine",
    version="0.2.0",
    description="Local synthetic compliance analysis prototype; no production deployment.",
)


def require_access_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> None:
    expected = get_settings().cidan_access_token
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="API access is not configured. Set CIDAN_ACCESS_TOKEN.",
        )
    if (
        credentials is None
        or credentials.scheme.casefold() != "bearer"
        or not hmac.compare_digest(
            credentials.credentials.encode("utf-8"),
            expected.encode("utf-8"),
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="A valid bearer access token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ApprovalRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=128)
    note: str = Field(default="", max_length=2000)


@app.get("/health")
def health() -> dict[str, Any]:
    settings = get_settings()
    configured = settings.llm_configured and bool(settings.cidan_access_token)
    return {
        "status": "ready" if configured else "needs_configuration",
        "llm_configured": settings.llm_configured,
        "access_control_configured": bool(settings.cidan_access_token),
        "llm_provider": "groq",
        "llm_model": settings.llm_model,
        "embedding_model": settings.embedding_model,
        "embedding_provider": "fastembed_local",
        "source_directory": str(settings.source_pdf_directory),
        "message": (
            None if configured
            else "Configure GROQ_API_KEY and CIDAN_ACCESS_TOKEN before using protected API operations."
        ),
    }


@app.get("/documents")
def documents(_: None = Depends(require_access_token)) -> dict[str, Any]:
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


@app.post("/documents/upload", status_code=201)
async def upload_documents(
    handbook: UploadFile = File(..., description="Text-readable PDF handbook/policy"),
    circular: UploadFile = File(..., description="Text-readable PDF circular/regulation"),
    _: None = Depends(require_access_token),
) -> dict[str, Any]:
    settings = get_settings()
    uploads = [
        (handbook, "policy_handbook"),
        (circular, "circular"),
    ]
    validated: list[tuple[UploadFile, str, bytes]] = []
    for upload, expected_type in uploads:
        filename = Path((upload.filename or "").replace("\\", "/")).name
        if not filename or Path(filename).suffix.casefold() != ".pdf":
            raise HTTPException(status_code=400, detail="Upload exactly two PDF files.")
        if classify_document(Path(filename)) != expected_type:
            expected_label = (
                "handbook/policy/rules"
                if expected_type == "policy_handbook"
                else "circular/regulatory/rbi"
            )
            raise HTTPException(
                status_code=400,
                detail=f"{expected_type} file name must contain one of: {expected_label}.",
            )
        content = await upload.read(settings.max_pdf_bytes + 1)
        if len(content) > settings.max_pdf_bytes:
            raise HTTPException(status_code=413, detail=f"{filename} exceeds the 25 MB limit.")
        validated.append((upload, filename, content))

    if validated[0][1].casefold() == validated[1][1].casefold():
        raise HTTPException(status_code=400, detail="Use distinct filenames for the two PDFs.")

    source_directory = settings.source_pdf_directory
    source_directory.mkdir(parents=True, exist_ok=True)
    staged_files: list[tuple[Path, str]] = []
    try:
        with tempfile.TemporaryDirectory(prefix=".cidan-upload-", dir=source_directory) as staging:
            staging_directory = Path(staging)
            for index, (_, filename, content) in enumerate(validated):
                staged_path = staging_directory / f"validated-{index}.pdf"
                staged_path.write_bytes(content)
                load_pdf(staged_path, settings.max_pdf_bytes)
                staged_files.append((staged_path, filename))

            for old_pdf in source_directory.glob("*.pdf"):
                old_pdf.unlink()
            for staged_path, filename in staged_files:
                staged_path.replace(source_directory / filename)
    except (OSError, ValueError) as exc:
        logger.exception("Source PDF upload failed")
        raise HTTPException(
            status_code=400,
            detail=f"Could not store or validate uploaded PDFs: {exc}",
        ) from exc

    return {
        "message": "Both source PDFs were stored. Run POST /ingest before analysis.",
        "documents": [
            {"filename": filename, "document_type": expected_type}
            for (_, filename, _), expected_type in zip(validated, ("policy_handbook", "circular"))
        ],
        "source_directory": str(source_directory),
    }


@app.post("/ingest")
def ingest_documents(_: None = Depends(require_access_token)) -> dict[str, Any]:
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
def analyze(_: None = Depends(require_access_token)) -> dict[str, Any]:
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
def workflows(_: None = Depends(require_access_token)) -> list[dict[str, Any]]:
    return [
        {
            "workflow_id": workflow["workflow_id"],
            "stage": workflow.get("stage"),
            "error": workflow.get("error"),
        }
        for workflow in list_workflows()
    ]


@app.get("/workflows/{workflow_id}")
def workflow_result(
    workflow_id: str,
    _: None = Depends(require_access_token),
) -> dict[str, Any]:
    try:
        return load_workflow(workflow_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/workflows/{workflow_id}/report")
def workflow_report(
    workflow_id: str,
    _: None = Depends(require_access_token),
) -> dict[str, Any]:
    result = workflow_result(workflow_id)
    if "report" not in result:
        raise HTTPException(status_code=409, detail="Report is unavailable because the workflow did not complete.")
    return result["report"]


@app.get("/workflows/{workflow_id}/report/markdown")
def workflow_report_markdown(
    workflow_id: str,
    _: None = Depends(require_access_token),
) -> PlainTextResponse:
    report = workflow_report(workflow_id)
    return PlainTextResponse(render_markdown(report), media_type="text/markdown")


@app.get("/rules")
def rules(_: None = Depends(require_access_token)) -> list[dict[str, Any]]:
    return [
        {"workflow_id": workflow["workflow_id"], **proposal}
        for workflow in list_workflows()
        for proposal in workflow.get("proposals", [])
    ]


@app.get("/rules/{rule_id}")
def get_rule(
    rule_id: str,
    _: None = Depends(require_access_token),
) -> dict[str, Any]:
    for workflow in list_workflows():
        for proposal in workflow.get("proposals", []):
            if proposal.get("rule_id") == rule_id:
                return {"workflow_id": workflow["workflow_id"], **proposal}
    raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")


@app.post("/rules/{rule_id}/approve")
def approve(
    rule_id: str,
    request: ApprovalRequest,
    _: None = Depends(require_access_token),
) -> dict[str, Any]:
    try:
        return approve_rule(rule_id, request.reviewer_id, request.note)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/rules/{rule_id}/export-preview")
def preview_export(rule_id: str, _: None = Depends(require_access_token)) -> dict[str, Any]:
    try:
        return export_preview(rule_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
