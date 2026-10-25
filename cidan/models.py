from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Citation(StrictModel):
    document_id: str
    filename: str
    document_type: Literal["circular", "policy_handbook", "unknown"]
    page: int
    excerpt: str
    chunk_id: str


class Obligation(StrictModel):
    obligation_id: str
    clause_id: str
    text: str
    applicability: str
    product_type: str
    amount_threshold: StrictFloat | StrictInt | None = None
    currency: str | None = None
    effective_date: str = "not_specified"
    responsible_function: str
    required_action: str
    deadline_or_frequency: str = "not_specified"
    exceptions: list[str] = Field(default_factory=list)
    source: Citation
    supporting_excerpt: str
    confidence: float = Field(ge=0, le=1)
    ambiguities: list[str] = Field(default_factory=list)
    source_label: Literal["synthetic_demo_source"] = "synthetic_demo_source"
    status: str = "needs_review"


class PolicyFinding(StrictModel):
    obligation_id: str
    status: Literal[
        "covered", "partially_covered", "not_found",
        "potential_conflict", "requires_human_review"
    ]
    matching_policy_provision: str | None = None
    circular_citation: Citation
    policy_citations: list[Citation] = Field(default_factory=list)
    reasoning: str
    missing_or_inconsistent: str
    operational_impact: str
    recommended_action: str
    confidence: float = Field(ge=0, le=1)
    evidence_limitations: list[str] = Field(default_factory=list)


class RuleCondition(StrictModel):
    field: Literal["amount", "retention_days", "is_emergency"]
    operator: Literal["gt", "gte", "lt", "lte", "eq", "ne"]
    value: StrictFloat | StrictInt | StrictBool


class RuleProposal(StrictModel):
    rule_id: str
    version: StrictInt = Field(ge=1)
    business_purpose: str
    source_obligation_ids: list[str] = Field(min_length=1)
    source_policy_references: list[str] = Field(default_factory=list)
    description: str
    trigger_conditions: list[RuleCondition] = Field(min_length=1)
    required_inputs: list[str] = Field(min_length=1)
    decision_outcomes: list[str] = Field(min_length=1)
    exceptions: list[str] = Field(default_factory=list)
    effective_date: str = "not_specified"
    assumptions: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    risk_level: Literal["low", "medium", "high", "undetermined"] = "undetermined"
    validation_criteria: list[str] = Field(min_length=1)
    rollback_considerations: str
    supporting_citations: list[Citation] = Field(min_length=1)
    action: Literal[
        "flag_review", "second_review", "require_exception_reason", "retention_gap"
    ]
    status: Literal["draft", "validated", "approved_for_export"] = "draft"


class MappingResult(StrictModel):
    obligation_id: str
    status: Literal[
        "covered", "partially_covered", "not_found",
        "potential_conflict", "requires_human_review"
    ]
    policy_refs: list[str] = Field(default_factory=list)
    explanation: str
    evidence: list[str] = Field(default_factory=list)

class ProposedRule(StrictModel):
    rule_id: str
    version: int = 1
    obligation_id: str
    source_clause: str
    field: str
    operator: Literal["gt", "gte", "lt", "lte", "eq", "ne"]
    value: Any
    action: Literal["flag_review", "second_review", "require_exception_reason", "retention_gap"]
    description: str
    status: str = "draft"


class SyntheticTestCase(StrictModel):
    test_id: str
    inputs: dict[str, Any]
    expected_result: bool
    reason: str
    source_obligation_id: str
    category: Literal[
        "positive", "negative", "threshold_boundary", "missing_input",
        "invalid_type", "exception", "ambiguous", "regression"
    ]
    synthetic: Literal[True] = True


class TestResult(StrictModel):
    transaction_id: str
    rule_id: str
    passed: bool
    expected: Any
    actual: Any
    message: str


class TestSummary(StrictModel):
    total: int
    passed: int
    failed: int
    skipped: int
    invalid: int
    pass_rate: float | None
    results: list[TestResult]


class ApprovalRecord(StrictModel):
    rule_id: str
    version: int
    reviewer_id: str = Field(min_length=1, max_length=128)
    decision: Literal["approve"]
    approved_at: datetime
    note: str = ""
