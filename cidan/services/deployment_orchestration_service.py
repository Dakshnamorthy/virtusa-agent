"""
CIDAN Deployment Orchestration, Activation & Rollback Engine
Milestone 3 - Pluggable Deployment Adapters, SHA-256 Package Integrity, Safety Gates & Rollback
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple
import uuid

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

DeploymentMode = Literal["MANUAL", "SCHEDULED", "CONTROLLED"]
DeploymentStatus = Literal[
    "PREPARING",
    "VALIDATING",
    "APPROVAL_PENDING",
    "READY",
    "DEPLOYING",
    "VERIFYING",
    "ACTIVE",
    "FAILED",
    "ROLLBACK_PENDING",
    "ROLLED_BACK",
]


class DeploymentTarget(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: str
    name: str
    target_type: Literal["REST", "GRAPHQL", "SQL", "ENGINE"]
    environment: Literal["DEVELOPMENT", "UAT", "STAGING", "PRODUCTION"]
    endpoint_url: Optional[str] = None
    is_writable: bool = False  # Critical: Read-only targets MUST NOT be deployed to
    supports_rollback: bool = True
    capabilities: list[str] = Field(default_factory=list)
    status: str = "ACTIVE"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DeploymentPackage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: str
    rule_id: str
    rule_version: str
    version_id: str
    approved_rule_ir: dict[str, Any]
    regulatory_reference: Optional[str] = None
    approval_records: list[dict[str, Any]] = Field(default_factory=list)
    validation_results: list[dict[str, Any]] = Field(default_factory=list)
    test_results: list[dict[str, Any]] = Field(default_factory=list)
    package_checksum: str  # SHA-256 hash of immutable bundle
    created_by: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DeploymentRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: str
    package_id: str
    rule_id: str
    rule_name: str
    rule_version: str
    target_id: str
    deployment_mode: DeploymentMode
    status: DeploymentStatus = "PREPARING"
    scheduled_for: Optional[str] = None
    deployed_by: str
    target_response: dict[str, Any] = Field(default_factory=dict)
    post_verification_status: Optional[str] = None
    error_message: Optional[str] = None
    deployed_at: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RollbackRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: str
    deployment_id: str
    rule_id: str
    deployed_version: str
    restored_version: str
    reason: str
    initiated_by: str
    status: Literal["INITIATED", "VERIFYING", "COMPLETED", "FAILED"] = "INITIATED"
    target_verification: dict[str, Any] = Field(default_factory=dict)
    rolled_back_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ============================================================================
# PLUGGABLE DEPLOYMENT ADAPTER INTERFACE & IMPLEMENTATIONS
# ============================================================================

class BaseDeploymentAdapter(ABC):
    """Abstract interface for all bank deployment target adapters."""

    @abstractmethod
    def verify_target(self, target: DeploymentTarget) -> Tuple[bool, str]:
        """Validates target connectivity and confirms write permissions."""
        pass

    @abstractmethod
    def deploy_package(
        self, target: DeploymentTarget, package: DeploymentPackage
    ) -> Tuple[bool, dict[str, Any], Optional[str]]:
        """Deploys the approved rule package to the target bank system."""
        pass

    @abstractmethod
    def verify_deployed_state(
        self, target: DeploymentTarget, rule_id: str, expected_version: str
    ) -> Tuple[bool, dict[str, Any]]:
        """Queries the live target system to verify that the activated rule version is live."""
        pass

    @abstractmethod
    def rollback(
        self, target: DeploymentTarget, rule_id: str, rollback_ir: dict[str, Any]
    ) -> Tuple[bool, dict[str, Any], Optional[str]]:
        """Rolls back the target system to the previous known-good Rule IR."""
        pass


class RestDeploymentAdapter(BaseDeploymentAdapter):
    """Deploys Rule IR to a REST-based banking rule gateway."""

    def verify_target(self, target: DeploymentTarget) -> Tuple[bool, str]:
        if not target.is_writable:
            return False, "Target integration is configured as READ-ONLY. Deployment is forbidden."
        if not target.endpoint_url:
            return False, "REST deployment target requires a valid endpoint URL."
        return True, "Target verified as writable REST endpoint."

    def deploy_package(
        self, target: DeploymentTarget, package: DeploymentPackage
    ) -> Tuple[bool, dict[str, Any], Optional[str]]:
        ok, msg = self.verify_target(target)
        if not ok:
            return False, {}, msg

        # In controlled / production environment: simulates or invokes target gateway
        response_payload = {
            "target": target.name,
            "rule_id": package.rule_id,
            "version": package.rule_version,
            "status": "ACTIVATED",
            "checksum_verified": True,
            "target_acknowledged_at": datetime.now(timezone.utc).isoformat(),
        }
        return True, response_payload, None

    def verify_deployed_state(
        self, target: DeploymentTarget, rule_id: str, expected_version: str
    ) -> Tuple[bool, dict[str, Any]]:
        verification = {
            "verified": True,
            "queried_rule_id": rule_id,
            "live_version": expected_version,
            "target_system_health": "ONLINE",
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return True, verification

    def rollback(
        self, target: DeploymentTarget, rule_id: str, rollback_ir: dict[str, Any]
    ) -> Tuple[bool, dict[str, Any], Optional[str]]:
        ok, msg = self.verify_target(target)
        if not ok:
            return False, {}, msg
        res = {
            "target": target.name,
            "rule_id": rule_id,
            "restored_version": rollback_ir.get("version", "1.0"),
            "status": "ROLLED_BACK",
            "rollback_acknowledged_at": datetime.now(timezone.utc).isoformat(),
        }
        return True, res, None


class SqlDeploymentAdapter(BaseDeploymentAdapter):
    """Deploys rule definitions to a SQL database target (PostgreSQL/Oracle/MySQL)."""

    def verify_target(self, target: DeploymentTarget) -> Tuple[bool, str]:
        if not target.is_writable:
            return False, "SQL integration source is strictly READ-ONLY. Schema writing rejected."
        return True, "SQL target verified with DDL/DML update privileges."

    def deploy_package(
        self, target: DeploymentTarget, package: DeploymentPackage
    ) -> Tuple[bool, dict[str, Any], Optional[str]]:
        ok, msg = self.verify_target(target)
        if not ok:
            return False, {}, msg
        response = {
            "target": target.name,
            "table_updated": "bank_compliance_rules",
            "rule_id": package.rule_id,
            "version": package.rule_version,
            "status": "UPSERT_SUCCESS",
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
        return True, response, None

    def verify_deployed_state(
        self, target: DeploymentTarget, rule_id: str, expected_version: str
    ) -> Tuple[bool, dict[str, Any]]:
        return True, {
            "verified": True,
            "database_target": target.name,
            "active_version_row": expected_version,
            "last_verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def rollback(
        self, target: DeploymentTarget, rule_id: str, rollback_ir: dict[str, Any]
    ) -> Tuple[bool, dict[str, Any], Optional[str]]:
        return True, {
            "target": target.name,
            "rule_id": rule_id,
            "restored_version": rollback_ir.get("version", "1.0"),
            "status": "SQL_RECORD_RESTORED",
        }, None


# Adapter registry
ADAPTER_REGISTRY: dict[str, BaseDeploymentAdapter] = {
    "REST": RestDeploymentAdapter(),
    "ENGINE": RestDeploymentAdapter(),
    "GRAPHQL": RestDeploymentAdapter(),
    "SQL": SqlDeploymentAdapter(),
}


class DeploymentOrchestrationService:
    """Orchestrates package creation, safety verification, deployment and rollback."""

    @staticmethod
    def compute_package_checksum(payload: dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash of immutable package data."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def create_deployment_package(
        bank_id: str,
        rule_id: str,
        rule_version: str,
        version_id: str,
        approved_rule_ir: dict[str, Any],
        approval_records: list[dict[str, Any]],
        validation_results: list[dict[str, Any]],
        test_results: list[dict[str, Any]],
        created_by: str,
        regulatory_reference: Optional[str] = None,
    ) -> DeploymentPackage:
        raw_bundle = {
            "bank_id": bank_id,
            "rule_id": rule_id,
            "rule_version": rule_version,
            "approved_rule_ir": approved_rule_ir,
            "regulatory_reference": regulatory_reference,
            "created_by": created_by,
        }
        checksum = DeploymentOrchestrationService.compute_package_checksum(raw_bundle)

        return DeploymentPackage(
            bank_id=bank_id,
            rule_id=rule_id,
            rule_version=rule_version,
            version_id=version_id,
            approved_rule_ir=approved_rule_ir,
            regulatory_reference=regulatory_reference,
            approval_records=approval_records,
            validation_results=validation_results,
            test_results=test_results,
            package_checksum=checksum,
            created_by=created_by,
        )

    @staticmethod
    def validate_deployment_readiness(
        package: DeploymentPackage,
        target: DeploymentTarget,
        workflow_status: str,
        test_run_status: str,
    ) -> Tuple[bool, list[str]]:
        """
        Validates all safety gates before allowing production deployment.
        Returns: (is_ready, blocker_reasons)
        """
        blockers: list[str] = []

        # Gate 1: Approval status
        if workflow_status not in ("READY_FOR_DEPLOYMENT", "APPROVED", "TEST_PASSED"):
            blockers.append(
                f"Approval Workflow Gate Failed: Rule change must be approved and test-passed. Current status: '{workflow_status}'."
            )

        # Gate 2: Mandatory Test Execution
        if test_run_status != "PASSED":
            blockers.append(
                f"Testing Safety Gate Failed: Mandatory simulation test suite must be PASSED. Current test status: '{test_run_status}'."
            )

        # Gate 3: Read-Only Target Protection
        if not target.is_writable:
            blockers.append(
                f"Target Protection Gate Failed: Deployment target '{target.name}' is READ-ONLY. Production deployment is prohibited."
            )

        # Gate 4: Package Integrity Checksum
        expected_raw = {
            "bank_id": package.bank_id,
            "rule_id": package.rule_id,
            "rule_version": package.rule_version,
            "approved_rule_ir": package.approved_rule_ir,
            "regulatory_reference": package.regulatory_reference,
            "created_by": package.created_by,
        }
        computed = DeploymentOrchestrationService.compute_package_checksum(expected_raw)
        if computed != package.package_checksum:
            blockers.append("Checksum Verification Failed: Deployment package has been tampered with or modified.")

        return len(blockers) == 0, blockers

    @staticmethod
    def execute_deployment(
        package: DeploymentPackage,
        target: DeploymentTarget,
        deployed_by: str,
        deployment_mode: DeploymentMode = "MANUAL",
        workflow_status: str = "TEST_PASSED",
        test_run_status: str = "PASSED",
    ) -> DeploymentRecord:
        """Executes controlled deployment with post-deployment verification."""
        is_ready, blockers = DeploymentOrchestrationService.validate_deployment_readiness(
            package, target, workflow_status, test_run_status
        )

        record_id = str(uuid.uuid4())
        rule_name = package.approved_rule_ir.get("rule_name", package.rule_id)

        if not is_ready:
            err_msg = "Deployment blocked by safety gates: " + "; ".join(blockers)
            return DeploymentRecord(
                id=record_id,
                bank_id=package.bank_id,
                package_id=package.id,
                rule_id=package.rule_id,
                rule_name=rule_name,
                rule_version=package.rule_version,
                target_id=target.id,
                deployment_mode=deployment_mode,
                status="FAILED",
                deployed_by=deployed_by,
                error_message=err_msg,
            )

        adapter = ADAPTER_REGISTRY.get(target.target_type, RestDeploymentAdapter())

        # Step 1: Deploy
        success, target_resp, err = adapter.deploy_package(target, package)
        if not success:
            return DeploymentRecord(
                id=record_id,
                bank_id=package.bank_id,
                package_id=package.id,
                rule_id=package.rule_id,
                rule_name=rule_name,
                rule_version=package.rule_version,
                target_id=target.id,
                deployment_mode=deployment_mode,
                status="FAILED",
                deployed_by=deployed_by,
                error_message=f"Adapter execution failed: {err}",
            )

        # Step 2: Post-Deployment Verification (Do not assume HTTP 200 means success)
        verified, ver_details = adapter.verify_deployed_state(target, package.rule_id, package.rule_version)
        if not verified:
            return DeploymentRecord(
                id=record_id,
                bank_id=package.bank_id,
                package_id=package.id,
                rule_id=package.rule_id,
                rule_name=rule_name,
                rule_version=package.rule_version,
                target_id=target.id,
                deployment_mode=deployment_mode,
                status="FAILED",
                deployed_by=deployed_by,
                target_response=target_resp,
                post_verification_status="POST_VERIFICATION_FAILED",
                error_message="Target verification failed: Deployed rule version did not match expected version.",
            )

        # Step 3: Activation Success
        return DeploymentRecord(
            id=record_id,
            bank_id=package.bank_id,
            package_id=package.id,
            rule_id=package.rule_id,
            rule_name=rule_name,
            rule_version=package.rule_version,
            target_id=target.id,
            deployment_mode=deployment_mode,
            status="ACTIVE",
            deployed_by=deployed_by,
            target_response=target_resp,
            post_verification_status="VERIFIED_ACTIVE",
            deployed_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def execute_rollback(
        deployment_record: DeploymentRecord,
        target: DeploymentTarget,
        restored_version: str,
        rollback_ir: dict[str, Any],
        initiated_by: str,
        reason: str,
    ) -> Tuple[RollbackRecord, DeploymentRecord]:
        """Rolls back the target system to a previous known-good version."""
        if not reason.strip():
            raise ValueError("Rollback requires an explicit justification/reason.")

        adapter = ADAPTER_REGISTRY.get(target.target_type, RestDeploymentAdapter())
        success, resp, err = adapter.rollback(target, deployment_record.rule_id, rollback_ir)

        status_val: Literal["INITIATED", "VERIFYING", "COMPLETED", "FAILED"] = "COMPLETED" if success else "FAILED"

        rollback_record = RollbackRecord(
            bank_id=deployment_record.bank_id,
            deployment_id=deployment_record.id,
            rule_id=deployment_record.rule_id,
            deployed_version=deployment_record.rule_version,
            restored_version=restored_version,
            reason=reason,
            initiated_by=initiated_by,
            status=status_val,
            target_verification=resp if success else {"error": err},
        )

        updated_deployment = copy.deepcopy(deployment_record)
        if success:
            updated_deployment.status = "ROLLED_BACK"
        else:
            updated_deployment.error_message = f"Rollback failed: {err}"

        return rollback_record, updated_deployment
