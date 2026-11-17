"""
Comprehensive Unit & Integration Test Suite for CIDAN Milestone 3:
- Approval Workflow Engine (16-State Lifecycle & Separation of Duties)
- Rule Version Management (Immutability & Semantic Comparison)
- Rule Testing & Simulation Engine (Boundary, Positive, Negative & Regression)
- Deployment Orchestration (Pluggable Adapters, Safety Gates, Checksum & Post-Verification)
- Rollback Engine (Version Restoration & Justification Requirement)
- Compliance Audit Trail & Notifications
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from datetime import datetime, timezone

from cidan.services.approval_workflow_service import (
    ApprovalDecisionRecord,
    ApprovalStageConfig,
    ApprovalWorkflow,
    ApprovalWorkflowService,
)
from cidan.services.rule_version_service import (
    RuleVersion,
    RuleVersionComparison,
    RuleVersionService,
)
from cidan.services.rule_testing_service import (
    RuleTestCase,
    RuleTestRun,
    RuleTestSuite,
    RuleTestingService,
)
from cidan.services.deployment_orchestration_service import (
    DeploymentMode,
    DeploymentPackage,
    DeploymentRecord,
    DeploymentTarget,
    DeploymentOrchestrationService,
    RestDeploymentAdapter,
    SqlDeploymentAdapter,
)
from cidan.services.audit_notification_service import (
    AuditEvent,
    AuditTrailService,
    NotificationRecord,
    NotificationService,
)
from cidan.services.persistence_service import BackendPersistence


class TestMilestone3ApprovalWorkflow(unittest.TestCase):
    """Module 1 & 2: Approval Workflow Engine Tests."""

    def setUp(self):
        self.bank_id = "test-bank-01"
        self.rule_id = "AML-CASH-100"
        self.rule_ir = {
            "rule_id": self.rule_id,
            "rule_name": "High Value Cash Reporting",
            "category": "AML",
            "condition_tree": {
                "operator": "AND",
                "conditions": [{"field": "transaction_amount", "operator": "gte", "value": 500000.0}],
            },
            "actions": [{"action_type": "FLAG_REVIEW", "target": "transaction"}],
        }

    def test_workflow_lifecycle_draft_to_submitted(self):
        wf = ApprovalWorkflowService.create_workflow(
            bank_id=self.bank_id,
            rule_id=self.rule_id,
            rule_name="High Value Cash Reporting",
            author_id="author@apexbank.com",
            author_email="author@apexbank.com",
            rule_ir_snapshot=self.rule_ir,
        )
        self.assertEqual(wf.status, "DRAFT")
        self.assertEqual(len(wf.required_stages), 4)

        # Transition to SUBMITTED_FOR_REVIEW
        wf_sub, dec = ApprovalWorkflowService.transition_state(
            workflow=wf,
            new_status="SUBMITTED_FOR_REVIEW",
            actor_email="author@apexbank.com",
            actor_role="RULE_AUTHOR",
            comments="Submitting proposed cash threshold decrease to INR 500,000.",
        )
        self.assertEqual(wf_sub.status, "SUBMITTED_FOR_REVIEW")
        self.assertEqual(dec.previous_status, "DRAFT")
        self.assertEqual(dec.new_status, "SUBMITTED_FOR_REVIEW")

    def test_separation_of_duties_blocks_author_self_approval(self):
        wf = ApprovalWorkflowService.create_workflow(
            bank_id=self.bank_id,
            rule_id=self.rule_id,
            rule_name="High Value Cash Reporting",
            author_id="author@apexbank.com",
            author_email="author@apexbank.com",
            rule_ir_snapshot=self.rule_ir,
        )
        wf_sub, _ = ApprovalWorkflowService.transition_state(
            workflow=wf,
            new_status="SUBMITTED_FOR_REVIEW",
            actor_email="author@apexbank.com",
            actor_role="RULE_AUTHOR",
        )
        wf_rev, _ = ApprovalWorkflowService.transition_state(
            workflow=wf_sub,
            new_status="UNDER_REVIEW",
            actor_email="analyst@apexbank.com",
            actor_role="COMPLIANCE_ANALYST",
        )

        # Author attempting to approve their own rule MUST fail
        with self.assertRaises(PermissionError) as ctx:
            ApprovalWorkflowService.transition_state(
                workflow=wf_rev,
                new_status="APPROVED",
                actor_email="author@apexbank.com",  # Same as author_email!
                actor_role="COMPLIANCE_ANALYST",
            )
        self.assertIn("Separation of duties violation", str(ctx.exception))

    def test_rejection_and_changes_requested_workflows(self):
        wf = ApprovalWorkflowService.create_workflow(
            bank_id=self.bank_id,
            rule_id=self.rule_id,
            rule_name="High Value Cash Reporting",
            author_id="author@apexbank.com",
            author_email="author@apexbank.com",
            rule_ir_snapshot=self.rule_ir,
        )
        wf_sub, _ = ApprovalWorkflowService.transition_state(
            workflow=wf,
            new_status="SUBMITTED_FOR_REVIEW",
            actor_email="author@apexbank.com",
            actor_role="RULE_AUTHOR",
        )

        # Changes Requested
        wf_req, dec_req = ApprovalWorkflowService.transition_state(
            workflow=wf_sub,
            new_status="CHANGES_REQUESTED",
            actor_email="manager@apexbank.com",
            actor_role="COMPLIANCE_MANAGER",
            change_request_notes="Include reporting timeline parameter.",
        )
        self.assertEqual(wf_req.status, "CHANGES_REQUESTED")
        self.assertEqual(wf_req.change_request_notes, "Include reporting timeline parameter.")

        # Resubmit
        wf_resub, _ = ApprovalWorkflowService.transition_state(
            workflow=wf_req,
            new_status="RESUBMITTED",
            actor_email="author@apexbank.com",
            actor_role="RULE_AUTHOR",
            comments="Added reporting_days=7 parameter as requested.",
        )
        self.assertEqual(wf_resub.status, "RESUBMITTED")

        # Reject
        wf_rej, dec_rej = ApprovalWorkflowService.transition_state(
            workflow=wf_resub,
            new_status="REJECTED",
            actor_email="risk@apexbank.com",
            actor_role="RISK_OFFICER",
            rejection_reason="Bank policy prohibits this change at this time.",
        )
        self.assertEqual(wf_rej.status, "REJECTED")
        self.assertEqual(wf_rej.rejection_reason, "Bank policy prohibits this change at this time.")


class TestMilestone3RuleVersioning(unittest.TestCase):
    """Module 3: Rule Version Management Tests."""

    def test_semantic_version_bump_and_immutability(self):
        v1_num = RuleVersionService.calculate_next_version(None)
        self.assertEqual(v1_num, "1.0")

        v1_1_num = RuleVersionService.calculate_next_version("1.0", bump_type="minor")
        self.assertEqual(v1_1_num, "1.1")

        v2_num = RuleVersionService.calculate_next_version("1.1", bump_type="major")
        self.assertEqual(v2_num, "2.0")

    def test_deep_rule_ir_version_comparison(self):
        base_ir = {
            "rule_id": "KYC-001",
            "category": "KYC",
            "condition_tree": {
                "operator": "AND",
                "conditions": [{"field": "is_pep", "operator": "eq", "value": True}],
            },
            "actions": [{"action_type": "FLAG_REVIEW"}],
            "parameters": {"threshold": 1000},
        }
        target_ir = {
            "rule_id": "KYC-001",
            "category": "KYC",
            "condition_tree": {
                "operator": "AND",
                "conditions": [
                    {"field": "is_pep", "operator": "eq", "value": True},
                    {"field": "risk_rating", "operator": "gte", "value": 8},  # Added condition
                ],
            },
            "actions": [{"action_type": "BLOCK"}],  # Modified action
            "parameters": {"threshold": 2000},  # Modified param
        }

        base_ver = RuleVersion(
            rule_id="KYC-001",
            bank_id="test-bank-01",
            version_number="1.0",
            rule_ir_snapshot=base_ir,
            change_summary="Initial KYC rule",
            created_by="officer@apexbank.com",
        )
        target_ver = RuleVersion(
            rule_id="KYC-001",
            bank_id="test-bank-01",
            version_number="1.1",
            parent_version="1.0",
            rule_ir_snapshot=target_ir,
            change_summary="Added risk score condition and escalated to BLOCK",
            created_by="officer@apexbank.com",
        )

        cmp = RuleVersionService.compare_versions(base_ver, target_ver)
        self.assertEqual(cmp.rule_id, "KYC-001")
        self.assertEqual(cmp.base_version, "1.0")
        self.assertEqual(cmp.target_version, "1.1")
        self.assertTrue(cmp.has_breaking_changes)
        self.assertGreaterEqual(cmp.total_differences, 3)

        diff_types = {d.change_type for d in cmp.differences}
        self.assertIn("CONDITION_ADDED", diff_types)
        self.assertIn("ACTION_MODIFIED", diff_types)
        self.assertIn("PARAMETER_CHANGED", diff_types)


class TestMilestone3RuleTestingSimulation(unittest.TestCase):
    """Module 4: Rule Testing & Simulation Engine Tests."""

    def setUp(self):
        self.rule_ir = {
            "rule_id": "TEST-AML-500",
            "condition_tree": {
                "operator": "AND",
                "conditions": [
                    {"field": "transaction_amount", "operator": "gte", "value": 500000.0},
                    {"field": "is_international", "operator": "eq", "value": True},
                ],
            },
            "actions": [{"action_type": "FLAG_REVIEW", "target": "transaction"}],
        }

    def test_automatic_boundary_and_functional_case_generation(self):
        cases = RuleTestingService.generate_boundary_and_functional_cases(
            suite_id="suite-001",
            bank_id="test-bank-01",
            rule_ir=self.rule_ir,
        )
        self.assertGreaterEqual(len(cases), 5)
        test_types = {c.test_type for c in cases}
        self.assertIn("BOUNDARY", test_types)
        self.assertIn("POSITIVE", test_types)
        self.assertIn("NEGATIVE", test_types)
        self.assertIn("REGRESSION", test_types)

        # Boundary checks around 500,000 threshold
        boundary_cases = [c for c in cases if c.test_type == "BOUNDARY"]
        self.assertEqual(len(boundary_cases), 3)  # at, below, above

    def test_test_suite_execution_pass(self):
        suite = RuleTestSuite(
            id="suite-pass-01",
            bank_id="test-bank-01",
            rule_id="TEST-AML-500",
            rule_version="1.0",
            suite_name="AML Regression Suite",
            test_cases=[
                RuleTestCase(
                    suite_id="suite-pass-01",
                    bank_id="test-bank-01",
                    rule_id="TEST-AML-500",
                    test_type="POSITIVE",
                    scenario_name="Valid high-value international transfer",
                    input_data={"transaction_amount": 600000.0, "is_international": True},
                    expected_result={"triggered": True},
                ),
                RuleTestCase(
                    suite_id="suite-pass-01",
                    bank_id="test-bank-01",
                    rule_id="TEST-AML-500",
                    test_type="NEGATIVE",
                    scenario_name="Low-value domestic transfer",
                    input_data={"transaction_amount": 10000.0, "is_international": False},
                    expected_result={"triggered": False},
                ),
            ],
            created_by="qa@apexbank.com",
        )

        run = RuleTestingService.execute_test_suite(
            suite=suite,
            rule_ir_snapshot=self.rule_ir,
            started_by="qa@apexbank.com",
        )
        self.assertEqual(run.status, "PASSED")
        self.assertEqual(run.passed_tests, 2)
        self.assertEqual(run.failed_tests, 0)
        self.assertEqual(run.pass_percentage, 100.0)

    def test_test_suite_execution_failure_detection(self):
        suite = RuleTestSuite(
            id="suite-fail-01",
            bank_id="test-bank-01",
            rule_id="TEST-AML-500",
            rule_version="1.0",
            suite_name="Failing Test Suite",
            test_cases=[
                RuleTestCase(
                    suite_id="suite-fail-01",
                    bank_id="test-bank-01",
                    rule_id="TEST-AML-500",
                    test_type="POSITIVE",
                    scenario_name="Incorrect expectation asserting False for triggered rule",
                    input_data={"transaction_amount": 750000.0, "is_international": True},
                    expected_result={"triggered": False},  # Intentionally wrong expectation
                )
            ],
            created_by="qa@apexbank.com",
        )

        run = RuleTestingService.execute_test_suite(
            suite=suite,
            rule_ir_snapshot=self.rule_ir,
            started_by="qa@apexbank.com",
        )
        self.assertEqual(run.status, "FAILED")
        self.assertEqual(run.failed_tests, 1)
        self.assertEqual(run.pass_percentage, 0.0)
        self.assertIn("Assertion failed", run.results[0].error_message)


class TestMilestone3DeploymentAndRollback(unittest.TestCase):
    """Module 5, 6, 7: Deployment Orchestration, Activation & Rollback Tests."""

    def setUp(self):
        self.bank_id = "test-bank-01"
        self.rule_id = "AML-CASH-100"
        self.rule_ir = {
            "rule_id": self.rule_id,
            "rule_name": "High Value Cash Reporting",
            "condition_tree": {"operator": "AND", "conditions": []},
            "actions": [],
        }
        self.package = DeploymentOrchestrationService.create_deployment_package(
            bank_id=self.bank_id,
            rule_id=self.rule_id,
            rule_version="1.1",
            version_id="ver-1.1-uuid",
            approved_rule_ir=self.rule_ir,
            approval_records=[{"role": "RISK_OFFICER", "decision": "APPROVED"}],
            validation_results=[],
            test_results=[{"status": "PASSED"}],
            created_by="admin@apexbank.com",
        )

    def test_deployment_checksum_integrity(self):
        self.assertIsNotNone(self.package.package_checksum)
        self.assertEqual(len(self.package.package_checksum), 64)  # SHA-256 length

    def test_readonly_target_blocks_deployment(self):
        readonly_target = DeploymentTarget(
            bank_id=self.bank_id,
            name="Read-Only SQL Replica",
            target_type="SQL",
            environment="PRODUCTION",
            is_writable=False,  # Read-only!
        )
        is_ready, blockers = DeploymentOrchestrationService.validate_deployment_readiness(
            package=self.package,
            target=readonly_target,
            workflow_status="TEST_PASSED",
            test_run_status="PASSED",
        )
        self.assertFalse(is_ready)
        self.assertTrue(any("READ-ONLY" in b for b in blockers))

    def test_failed_tests_block_deployment(self):
        writable_target = DeploymentTarget(
            bank_id=self.bank_id,
            name="UAT REST Gateway",
            target_type="REST",
            environment="UAT",
            endpoint_url="https://uat.apexbank.internal/rules",
            is_writable=True,
        )
        # Attempting deployment when test status is FAILED
        is_ready, blockers = DeploymentOrchestrationService.validate_deployment_readiness(
            package=self.package,
            target=writable_target,
            workflow_status="APPROVED",
            test_run_status="FAILED",  # Safety Gate Violation!
        )
        self.assertFalse(is_ready)
        self.assertTrue(any("Testing Safety Gate Failed" in b for b in blockers))

    def test_controlled_deployment_execution_and_post_verification(self):
        writable_target = DeploymentTarget(
            bank_id=self.bank_id,
            name="UAT REST Gateway",
            target_type="REST",
            environment="UAT",
            endpoint_url="https://uat.apexbank.internal/rules",
            is_writable=True,
        )
        record = DeploymentOrchestrationService.execute_deployment(
            package=self.package,
            target=writable_target,
            deployed_by="deployer@apexbank.com",
            deployment_mode="CONTROLLED",
            workflow_status="TEST_PASSED",
            test_run_status="PASSED",
        )
        self.assertEqual(record.status, "ACTIVE")
        self.assertEqual(record.post_verification_status, "VERIFIED_ACTIVE")
        self.assertIsNotNone(record.deployed_at)

    def test_rollback_requires_reason_and_restores_version(self):
        writable_target = DeploymentTarget(
            bank_id=self.bank_id,
            name="UAT REST Gateway",
            target_type="REST",
            environment="UAT",
            endpoint_url="https://uat.apexbank.internal/rules",
            is_writable=True,
        )
        active_record = DeploymentRecord(
            bank_id=self.bank_id,
            package_id=self.package.id,
            rule_id=self.rule_id,
            rule_name="High Value Cash Reporting",
            rule_version="1.1",
            target_id=writable_target.id,
            deployment_mode="MANUAL",
            status="ACTIVE",
            deployed_by="deployer@apexbank.com",
        )

        # Rollback without reason must fail
        with self.assertRaises(ValueError):
            DeploymentOrchestrationService.execute_rollback(
                deployment_record=active_record,
                target=writable_target,
                restored_version="1.0",
                rollback_ir={"version": "1.0"},
                initiated_by="admin@apexbank.com",
                reason="   ",
            )

        # Rollback with valid reason
        rb_record, updated_record = DeploymentOrchestrationService.execute_rollback(
            deployment_record=active_record,
            target=writable_target,
            restored_version="1.0",
            rollback_ir={"version": "1.0"},
            initiated_by="admin@apexbank.com",
            reason="Unanticipated downstream alert volume surge detected in transaction pipeline.",
        )
        self.assertEqual(rb_record.status, "COMPLETED")
        self.assertEqual(rb_record.restored_version, "1.0")
        self.assertEqual(updated_record.status, "ROLLED_BACK")


class TestMilestone3AuditAndNotifications(unittest.TestCase):
    """Module 8 & 9: Audit Trail and Notification Tests."""

    def test_audit_event_recording_and_csv_export(self):
        ev = AuditTrailService.record_event(
            bank_id="apex-bank-01",
            actor_email="compliance@apexbank.com",
            actor_role="COMPLIANCE_OFFICER",
            action="RULE_APPROVED",
            resource_type="APPROVAL_WORKFLOW",
            resource_id="wf-12345",
            metadata={"rule_id": "AML-01", "decision": "APPROVED"},
        )
        self.assertEqual(ev.bank_id, "apex-bank-01")
        self.assertEqual(ev.action, "RULE_APPROVED")

        # Test CSV export
        csv_data = AuditTrailService.export_audit_csv([ev])
        self.assertIn("Event ID,Bank ID,Timestamp (UTC)", csv_data)
        self.assertIn("RULE_APPROVED", csv_data)
        self.assertIn("compliance@apexbank.com", csv_data)

    def test_notification_creation(self):
        notif = NotificationService.notify_lifecycle_event(
            bank_id="apex-bank-01",
            recipient_email="auditor@apexbank.com",
            event_type="APPROVAL_REQUIRED",
            title="Action Required: Review AML Policy Update",
            message="Please review proposed threshold modification for AML-100.",
            resource_id="wf-999",
            send_email=False,
        )
        self.assertEqual(notif.status, "SENT")
        self.assertFalse(notif.is_read)


if __name__ == "__main__":
    unittest.main()
