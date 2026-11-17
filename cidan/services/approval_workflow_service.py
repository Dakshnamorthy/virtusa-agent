"""
CIDAN Approval Workflow Service
Milestone 3 - 16-State Lifecycle Engine, Multi-Role Approvals, Separation of Duties & Deadlines
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Union
import uuid

from pydantic import BaseModel, ConfigDict, Field

# 16-State Lifecycle Definition
ApprovalStatus = Literal[
    "DRAFT",
    "SUBMITTED_FOR_REVIEW",
    "UNDER_REVIEW",
    "CHANGES_REQUESTED",
    "RESUBMITTED",
    "APPROVED",
    "REJECTED",
    "READY_FOR_TESTING",
    "TESTING_IN_PROGRESS",
    "TEST_FAILED",
    "TEST_PASSED",
    "READY_FOR_DEPLOYMENT",
    "DEPLOYMENT_IN_PROGRESS",
    "DEPLOYED",
    "DEPLOYMENT_FAILED",
    "ROLLED_BACK",
]

# Configurable Approval Roles
ApprovalRole = Literal[
    "RULE_AUTHOR",
    "COMPLIANCE_ANALYST",
    "COMPLIANCE_MANAGER",
    "RISK_OFFICER",
    "TECHNICAL_APPROVER",
    "DEPLOYMENT_ADMIN",
    "SYSTEM_ADMIN",
]

# Permitted State Transitions
VALID_TRANSITIONS: dict[ApprovalStatus, set[ApprovalStatus]] = {
    "DRAFT": {"SUBMITTED_FOR_REVIEW"},
    "SUBMITTED_FOR_REVIEW": {"UNDER_REVIEW", "CHANGES_REQUESTED", "REJECTED"},
    "UNDER_REVIEW": {"APPROVED", "CHANGES_REQUESTED", "REJECTED"},
    "CHANGES_REQUESTED": {"RESUBMITTED", "REJECTED"},
    "RESUBMITTED": {"UNDER_REVIEW", "CHANGES_REQUESTED", "REJECTED"},
    "APPROVED": {"READY_FOR_TESTING"},
    "REJECTED": {"DRAFT"},  # Author may restart from draft if re-initiated
    "READY_FOR_TESTING": {"TESTING_IN_PROGRESS"},
    "TESTING_IN_PROGRESS": {"TEST_PASSED", "TEST_FAILED"},
    "TEST_FAILED": {"READY_FOR_TESTING", "CHANGES_REQUESTED"},  # Rerun or request revision
    "TEST_PASSED": {"READY_FOR_DEPLOYMENT"},
    "READY_FOR_DEPLOYMENT": {"DEPLOYMENT_IN_PROGRESS"},
    "DEPLOYMENT_IN_PROGRESS": {"DEPLOYED", "DEPLOYMENT_FAILED"},
    "DEPLOYMENT_FAILED": {"READY_FOR_DEPLOYMENT", "CHANGES_REQUESTED"},
    "DEPLOYED": {"ROLLED_BACK"},
    "ROLLED_BACK": {"READY_FOR_TESTING", "CHANGES_REQUESTED"},
}


class ApprovalStageConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    stage_name: str
    required_role: ApprovalRole
    is_mandatory: bool = True
    assigned_email: Optional[str] = None
    deadline_hours: int = 48


class ApprovalDecisionRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str
    bank_id: str
    rule_id: str
    delta_id: Optional[str] = None
    stage_name: str
    approver_id: str
    approver_email: str
    approver_role: ApprovalRole
    decision: Literal["APPROVED", "REJECTED", "CHANGES_REQUESTED", "RESUBMITTED"]
    comments: str = ""
    previous_status: ApprovalStatus
    new_status: ApprovalStatus
    decided_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ApprovalWorkflow(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: str
    delta_id: Optional[str] = None
    rule_id: str
    rule_name: str
    category: str = "GENERAL"
    circular_reference: Optional[str] = None
    author_id: str
    author_email: str
    status: ApprovalStatus = "DRAFT"
    current_stage_index: int = 0
    required_stages: list[ApprovalStageConfig] = Field(default_factory=list)
    rule_ir_snapshot: dict[str, Any] = Field(default_factory=dict)
    deadline: Optional[Union[str, datetime]] = None
    rejection_reason: Optional[str] = None
    change_request_notes: Optional[str] = None
    created_at: Union[str, datetime] = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: Union[str, datetime] = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def get_default_approval_stages() -> list[ApprovalStageConfig]:
    """Default enterprise multi-level approval pipeline."""
    return [
        ApprovalStageConfig(stage_name="Compliance Analyst Review", required_role="COMPLIANCE_ANALYST", deadline_hours=24),
        ApprovalStageConfig(stage_name="Compliance Manager Sign-Off", required_role="COMPLIANCE_MANAGER", deadline_hours=48),
        ApprovalStageConfig(stage_name="Risk Officer Adjudication", required_role="RISK_OFFICER", deadline_hours=48),
        ApprovalStageConfig(stage_name="Technical Architecture Verification", required_role="TECHNICAL_APPROVER", deadline_hours=24),
    ]


class ApprovalWorkflowService:
    """Manages the full 16-state lifecycle and multi-stage approvals."""

    @staticmethod
    def create_workflow(
        bank_id: str,
        rule_id: str,
        rule_name: str,
        author_id: str,
        author_email: str,
        rule_ir_snapshot: dict[str, Any],
        delta_id: Optional[str] = None,
        category: str = "GENERAL",
        circular_reference: Optional[str] = None,
        custom_stages: Optional[list[ApprovalStageConfig]] = None,
        deadline_days: int = 7,
    ) -> ApprovalWorkflow:
        stages = custom_stages or get_default_approval_stages()
        deadline = (datetime.now(timezone.utc) + timedelta(days=deadline_days)).isoformat()

        wf = ApprovalWorkflow(
            bank_id=bank_id,
            delta_id=delta_id,
            rule_id=rule_id,
            rule_name=rule_name,
            category=category,
            circular_reference=circular_reference,
            author_id=author_id,
            author_email=author_email,
            status="DRAFT",
            current_stage_index=0,
            required_stages=stages,
            rule_ir_snapshot=rule_ir_snapshot,
            deadline=deadline,
        )
        return wf

    @staticmethod
    def transition_state(
        workflow: ApprovalWorkflow,
        new_status: ApprovalStatus,
        actor_email: str,
        actor_role: ApprovalRole,
        comments: str = "",
        rejection_reason: Optional[str] = None,
        change_request_notes: Optional[str] = None,
    ) -> tuple[ApprovalWorkflow, ApprovalDecisionRecord]:
        curr_status = workflow.status

        # Validate transition matrix
        allowed = VALID_TRANSITIONS.get(curr_status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Invalid workflow transition from '{curr_status}' to '{new_status}'. Allowed transitions: {sorted(allowed)}"
            )

        # Separation of Duties check
        # Rule Author cannot approve their own rule in review stages
        if new_status == "APPROVED" and workflow.author_email.lower() == actor_email.lower():
            if actor_role != "SYSTEM_ADMIN":
                raise PermissionError("Separation of duties violation: Rule author cannot approve their own submission.")

        # Update workflow record
        updated_wf = copy.deepcopy(workflow)
        updated_wf.status = new_status
        updated_wf.updated_at = datetime.now(timezone.utc).isoformat()

        if rejection_reason:
            updated_wf.rejection_reason = rejection_reason
        if change_request_notes:
            updated_wf.change_request_notes = change_request_notes

        decision_type: Literal["APPROVED", "REJECTED", "CHANGES_REQUESTED", "RESUBMITTED"] = "APPROVED"
        if new_status == "REJECTED":
            decision_type = "REJECTED"
        elif new_status == "CHANGES_REQUESTED":
            decision_type = "CHANGES_REQUESTED"
        elif new_status == "RESUBMITTED":
            decision_type = "RESUBMITTED"

        current_stage = (
            workflow.required_stages[workflow.current_stage_index].stage_name
            if workflow.required_stages and workflow.current_stage_index < len(workflow.required_stages)
            else "General Review"
        )

        decision = ApprovalDecisionRecord(
            workflow_id=workflow.id,
            bank_id=workflow.bank_id,
            rule_id=workflow.rule_id,
            delta_id=workflow.delta_id,
            stage_name=current_stage,
            approver_id=actor_email,
            approver_email=actor_email,
            approver_role=actor_role,
            decision=decision_type,
            comments=comments,
            previous_status=curr_status,
            new_status=new_status,
        )

        # Advance stage index if approved and more stages remain
        if new_status == "APPROVED" and updated_wf.current_stage_index + 1 < len(updated_wf.required_stages):
            # If multi-stage, advance stage and keep under review until final stage
            updated_wf.current_stage_index += 1
            updated_wf.status = "UNDER_REVIEW"

        return updated_wf, decision
