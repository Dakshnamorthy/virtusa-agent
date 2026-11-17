import hmac
import logging
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from cidan.config import ConfigurationError, get_settings
from cidan.ingestion.pdf_loader import classify_document, find_pdfs, ingestion_status, load_pdf
from cidan.services.approval_service import approve_rule, export_preview
from cidan.services.delta_analysis_service import (
    DeltaAnalysisResult,
    DiffItem,
    RuleDelta,
    run_delta_analysis,
)
from cidan.services.integration_service import (
    CrossBankAccessDeniedError,
    DatabaseConnectionError,
    ExistingRuleDto,
    FetchRulesRequest,
    IntegrationService,
    IntegrationVerifyRequest,
    IntegrationVerifyResponse,
    SchemaInspectRequest,
    SchemaInspectResponse,
    UnverifiedSourceError,
)
from cidan.services.rule_ir_service import (
    ActionNode,
    ConditionNode,
    ConditionTree,
    RuleIR,
    extract_obligations_from_circular,
    extract_rules_from_existing_content,
    normalize_to_rule_ir,
)
from cidan.services.rule_validation_service import (
    ValidationFinding,
    validate_rule_ir,
)
from cidan.workflow.persistence import load_workflow, list_workflows

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)
app = FastAPI(
    title="CIDAN - Regulatory Circular to Live Rule Engine",
    version="0.2.0",
    description="Local synthetic compliance analysis prototype; no production deployment.",
)


class AuthenticatedUser(BaseModel):
    user_email: str = "auditor@apexbank.com"
    bank_id: str = "apex-bank-01"
    role: str = "COMPLIANCE_AUDITOR"


def require_authenticated_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthenticatedUser:
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
    return AuthenticatedUser()


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
        "llm_max_output_tokens": settings.llm_max_output_tokens,
        "embedding_model": settings.embedding_model,
        "embedding_provider": "fastembed_local",
        "source_directory": str(settings.source_pdf_directory),
        "message": (
            None if configured
            else "Configure LLM credentials and CIDAN_ACCESS_TOKEN before using protected API operations."
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
        from cidan.ingestion.vector_store import ingest

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
        from cidan.services.workflow_service import execute_workflow

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
    from cidan.agents.reporting import render_markdown

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


# ============================================================================
# MILESTONE 1: BANKING INTEGRATION ENDPOINTS
# ============================================================================


@app.post(
    "/integrations/verify",
    response_model=IntegrationVerifyResponse,
    summary="Verify Banking Integration Source Connection",
    description="Securely verifies connection to REST, GraphQL, SQL, or NoSQL sources with strict timeouts.",
)
def verify_integration(
    request: IntegrationVerifyRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> IntegrationVerifyResponse:
    try:
        return IntegrationService.verify_connection(request, authorized_bank_id=user.bank_id)
    except CrossBankAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post(
    "/integrations/inspect-schema",
    response_model=SchemaInspectResponse,
    summary="Inspect Integration Source Schema",
    description="Safely inspects tables, collections, and metadata for a verified integration source.",
)
def inspect_schema(
    request: SchemaInspectRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> SchemaInspectResponse:
    try:
        return IntegrationService.inspect_schema(request, authorized_bank_id=user.bank_id)
    except UnverifiedSourceError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except CrossBankAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except DatabaseConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post(
    "/integrations/fetch-rules",
    response_model=list[ExistingRuleDto],
    summary="Fetch Existing Compliance Rules",
    description="Safely retrieves sample active rules for a bank tenant with zero arbitrary SQL execution.",
)
def fetch_rules(
    request: FetchRulesRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[ExistingRuleDto]:
    try:
        return IntegrationService.fetch_rules(request, authorized_bank_id=user.bank_id)
    except UnverifiedSourceError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except CrossBankAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except DatabaseConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ============================================================================
# MILESTONE 2: AI RULE ANALYSIS, UNIVERSAL RULE IR & DELTA ANALYSIS
# ============================================================================

# Thread-safe bank-isolated stores for Milestone 2 objects
_BANK_RULE_IR_STORE: dict[str, list[RuleIR]] = {}
_BANK_DELTA_ANALYSES_STORE: dict[str, list[DeltaAnalysisResult]] = {}
_BANK_MAPPINGS_STORE: dict[str, list[dict[str, Any]]] = {}
_BANK_VALIDATIONS_STORE: dict[str, list[ValidationFinding]] = {}


class ExtractExistingRulesRequest(BaseModel):
    content: str = Field(min_length=1, description="Raw document or extracted rule content")
    filename: str = Field(default="rules.txt", min_length=1)
    file_format: str = Field(default="txt", min_length=1)
    bank_id: str | None = None


class ExtractCircularRequest(BaseModel):
    circular_text: str = Field(min_length=1, description="Raw regulatory circular text")
    circular_number: str = Field(min_length=1, description="Circular identification number")
    authority: str = Field(default="RBI", min_length=1)
    filename: str = Field(default="circular.pdf", min_length=1)
    bank_id: str | None = None


class DeltaAnalysisRequest(BaseModel):
    analysis_name: str = Field(default="Regulatory Circular Delta Analysis", min_length=1)
    circular_id: str | None = None
    circular_number: str | None = None
    circular_text: str | None = None
    circular_obligations: list[dict[str, Any]] | None = None
    existing_rules: list[dict[str, Any]] | None = None
    bank_id: str | None = None


class SaveMappingRequest(BaseModel):
    delta_id: str = Field(min_length=1)
    decision: str = Field(pattern="^(ACCEPTED|MODIFIED|REJECTED|MANUAL_REVIEW)$")
    customized_rule_ir: dict[str, Any] | None = None
    user_notes: str | None = None
    bank_id: str | None = None


class ValidateRuleRequest(BaseModel):
    rule: dict[str, Any]
    delta_id: str | None = None
    bank_id: str | None = None


@app.post(
    "/rules/extract-existing",
    response_model=list[RuleIR],
    summary="Extract Structured Rules from Existing Bank Documents",
    description="Extracts normalized Universal Rule IR items with conditions and traceability from JSON, SQL, or text documents.",
)
def extract_existing_rules_endpoint(
    request: ExtractExistingRulesRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[RuleIR]:
    if request.bank_id and request.bank_id != user.bank_id:
        raise HTTPException(status_code=403, detail="Cross-bank access denied.")

    extracted = extract_rules_from_existing_content(
        content=request.content,
        filename=request.filename,
        file_format=request.file_format,
        bank_id=user.bank_id,
    )
    
    # Cache in bank-scoped store
    store = _BANK_RULE_IR_STORE.setdefault(user.bank_id, [])
    for rule in extracted:
        # Avoid duplicate rule_ids
        if not any(r.rule_id == rule.rule_id for r in store):
            store.append(rule)
            
    return extracted


@app.post(
    "/rules/extract-circular",
    response_model=list[dict[str, Any]],
    summary="Extract Obligations and Candidate Rules from Circular",
    description="Extracts regulatory obligations, mandatory clauses, deadlines, and candidate Rule IR structures.",
)
def extract_circular_endpoint(
    request: ExtractCircularRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[dict[str, Any]]:
    if request.bank_id and request.bank_id != user.bank_id:
        raise HTTPException(status_code=403, detail="Cross-bank access denied.")

    return extract_obligations_from_circular(
        circular_text=request.circular_text,
        circular_number=request.circular_number,
        authority=request.authority,
        filename=request.filename,
        bank_id=user.bank_id,
    )


@app.post(
    "/rules/normalize-ir",
    response_model=RuleIR,
    summary="Normalize Raw Rule to Universal Rule IR",
    description="Validates and normalizes condition tree, actions, and metadata into strict Universal Rule IR.",
)
def normalize_ir_endpoint(
    raw_rule: dict[str, Any],
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> RuleIR:
    rule_ir = normalize_to_rule_ir(raw_rule)
    rule_ir.bank_id = user.bank_id
    return rule_ir


@app.get(
    "/rules/ir",
    response_model=list[RuleIR],
    summary="Get Bank Universal Rule IR Catalog",
    description="Retrieves active Universal Rule IR rules for the authenticated bank.",
)
def get_rule_ir_catalog(
    category: str | None = None,
    source_type: str | None = None,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[RuleIR]:
    rules = _BANK_RULE_IR_STORE.get(user.bank_id, [])
    if category:
        rules = [r for r in rules if r.category.upper() == category.upper()]
    if source_type:
        rules = [r for r in rules if r.source_type.upper() == source_type.upper()]
    return rules


@app.post(
    "/deltas/analyze",
    response_model=DeltaAnalysisResult,
    summary="Run AI-Powered Regulatory Delta Analysis",
    description="Compares bank existing rules with circular requirements, categorizes changes into 6 classes, and generates explainable diffs.",
)
def analyze_deltas_endpoint(
    request: DeltaAnalysisRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> DeltaAnalysisResult:
    if request.bank_id and request.bank_id != user.bank_id:
        raise HTTPException(status_code=403, detail="Cross-bank access denied.")

    # 1. Fetch or parse existing bank rules
    bank_existing: list[RuleIR] = []
    if request.existing_rules:
        bank_existing = [normalize_to_rule_ir(r) for r in request.existing_rules]
    else:
        bank_existing = _BANK_RULE_IR_STORE.get(user.bank_id, [])

    # If empty, extract default baseline rules for realistic banking evaluation
    if not bank_existing:
        default_baseline = (
            "1. High Value Cash Transaction: Mandatory reporting for cash transactions >= INR 1,000,000 within 15 days.\n"
            "2. Suspicious Pattern Alert: Monitor unusual rapid deposits exceeding INR 500,000.\n"
            "3. Cross Border Wire Transfer: Dual officer approval required for outward remittances > USD 50,000."
        )
        bank_existing = extract_rules_from_existing_content(
            content=default_baseline,
            filename="baseline_rules.txt",
            file_format="txt",
            bank_id=user.bank_id,
        )
        _BANK_RULE_IR_STORE[user.bank_id] = list(bank_existing)

    # 2. Fetch or extract circular obligations
    obligations = request.circular_obligations or []
    if not obligations and request.circular_text:
        obligations = extract_obligations_from_circular(
            circular_text=request.circular_text,
            circular_number=request.circular_number or "CIRCULAR-01",
            authority="RBI",
            bank_id=user.bank_id,
        )

    # 3. Execute Delta Analysis
    result = run_delta_analysis(
        bank_id=user.bank_id,
        existing_rules=bank_existing,
        circular_obligations=obligations,
        analysis_name=request.analysis_name,
        circular_id=request.circular_id,
        circular_number=request.circular_number,
    )

    # Cache analysis result
    _BANK_DELTA_ANALYSES_STORE.setdefault(user.bank_id, []).append(result)

    return result


@app.get(
    "/deltas",
    response_model=list[DeltaAnalysisResult],
    summary="List Regulatory Delta Analyses for Bank",
    description="Retrieves historical delta analysis summaries and counts for the authenticated bank.",
)
def list_deltas_endpoint(
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[DeltaAnalysisResult]:
    return _BANK_DELTA_ANALYSES_STORE.get(user.bank_id, [])


@app.get(
    "/deltas/{delta_id}",
    response_model=RuleDelta,
    summary="Get Specific Rule Delta Details",
    description="Retrieves visual differences, explainable AI reasoning, and evidence sources for a specific delta item.",
)
def get_delta_item_endpoint(
    delta_id: str,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> RuleDelta:
    analyses = _BANK_DELTA_ANALYSES_STORE.get(user.bank_id, [])
    for analysis in analyses:
        for delta in analysis.deltas:
            if delta.id == delta_id:
                return delta
    raise HTTPException(status_code=404, detail=f"Rule delta not found: {delta_id}")


@app.post(
    "/deltas/mappings/save",
    summary="Save Human Review Mapping Decision",
    description="Records human compliance officer acceptance, modification, or rejection for a proposed rule change.",
)
def save_mapping_endpoint(
    request: SaveMappingRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> dict[str, Any]:
    if request.bank_id and request.bank_id != user.bank_id:
        raise HTTPException(status_code=403, detail="Cross-bank access denied.")

    # Update delta status in memory
    analyses = _BANK_DELTA_ANALYSES_STORE.get(user.bank_id, [])
    target_delta: RuleDelta | None = None
    for analysis in analyses:
        for delta in analysis.deltas:
            if delta.id == request.delta_id:
                target_delta = delta
                status_map = {
                    "ACCEPTED": "ACCEPTED",
                    "MODIFIED": "MODIFIED",
                    "REJECTED": "REJECTED",
                    "MANUAL_REVIEW": "NEEDS_REVIEW",
                }
                delta.review_status = status_map.get(request.decision, "PENDING")
                if request.customized_rule_ir:
                    delta.proposed_change = request.customized_rule_ir
                break

    mapping_record = {
        "mapping_id": str(uuid.uuid4()),
        "bank_id": user.bank_id,
        "delta_id": request.delta_id,
        "user_email": user.user_email,
        "decision": request.decision,
        "customized_rule_ir": request.customized_rule_ir,
        "user_notes": request.user_notes,
    }
    _BANK_MAPPINGS_STORE.setdefault(user.bank_id, []).append(mapping_record)

    return {
        "status": "SUCCESS",
        "message": f"Mapping decision '{request.decision}' successfully saved.",
        "mapping": mapping_record,
        "delta_updated": target_delta is not None,
    }


@app.post(
    "/rules/validate",
    response_model=list[ValidationFinding],
    summary="Validate Rule IR",
    description="Executes structural, logical, and regulatory checks on a Rule IR, detecting contradictions, boundary inversions, and missing constraints.",
)
def validate_rule_endpoint(
    request: ValidateRuleRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[ValidationFinding]:
    if request.bank_id and request.bank_id != user.bank_id:
        raise HTTPException(status_code=403, detail="Cross-bank access denied.")

    findings = validate_rule_ir(
        rule=request.rule,
        delta_id=request.delta_id,
        bank_id=user.bank_id,
    )
    _BANK_VALIDATIONS_STORE.setdefault(user.bank_id, []).extend(findings)
    return findings


@app.get(
    "/rules/validations",
    response_model=list[ValidationFinding],
    summary="Get Rule Validation Findings",
    description="Retrieves validation findings for the authenticated bank.",
)
def get_validations_endpoint(
    delta_id: str | None = None,
    user: AuthenticatedUser = Depends(require_authenticated_user),
) -> list[ValidationFinding]:
    findings = _BANK_VALIDATIONS_STORE.get(user.bank_id, [])
    if delta_id:
        findings = [f for f in findings if f.delta_id == delta_id]
    return findings

