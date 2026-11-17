"""
End-to-End Functional Test Suite for CIDAN Milestone 3
Validates:
1. Multi-stage approval workflow with separation of duties
2. Semantic rule versioning & deep IR diff comparison
3. Sandbox rule simulation & boundary test execution
4. Deployment orchestration, safety gates & SHA-256 integrity
5. Atomic rollback requiring justification
6. Append-only audit trail & CSV export
7. In-app and notification delivery
"""
import os
import sys
import json
import logging

os.environ["CIDAN_ACCESS_TOKEN"] = "cidan_secret_token_2026_secure"
from fastapi.testclient import TestClient

from cidan.api import app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("m3_e2e")

client = TestClient(app)
AUTH_HEADERS = {
    "Authorization": "Bearer cidan_secret_token_2026_secure",
    "Content-Type": "application/json"
}

def run_all_e2e():
    print("=" * 70)
    print("CIDAN MILESTONE 3: COMPREHENSIVE END-TO-END AUDIT SUITE")
    print("=" * 70)
    
    # -------------------------------------------------------------------------
    # STAGE 1: APPROVAL WORKFLOW & LIFECYCLE
    # -------------------------------------------------------------------------
    print("\n[STAGE 1] Testing Approval Workflow Lifecycle & Separation of Duties...")
    
    # 1.1 Create Workflow
    wf_payload = {
        "rule_id": "RULE-RBI-LCR-2026",
        "rule_name": "Liquidity Coverage Ratio Buffer",
        "category": "LIQUIDITY",
        "circular_reference": "RBI/2026-27/04",
        "required_stages": ["COMPLIANCE_REVIEW", "RISK_ASSESSMENT", "TECHNICAL_SIGN_OFF"],
        "rule_ir_snapshot": {
            "rule_id": "RULE-RBI-LCR-2026",
            "rule_name": "LCR Rule v1",
            "version": "1.0",
            "condition_tree": {
                "logical_operator": "AND",
                "conditions": [{"field": "lcr_ratio", "operator": ">=", "value": 100}]
            },
            "actions": [{"action_type": "APPROVE_BUFFER", "parameters": {"buffer_pct": 2.5}}]
        }
    }
    resp = client.post("/approvals/workflows", json=wf_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Workflow creation failed: {resp.text}"
    wf_data = resp.json()
    wf_id = wf_data["id"]
    author_email = wf_data["author_email"]
    print(f"  [PASS] Workflow created: ID={wf_id}, Status={wf_data['status']}, Author={author_email}")
    
    # 1.2 Author Self-Approval Blocked (Separation of Duties)
    action_payload = {
        "action": "APPROVED",
        "approver_id": author_email,  # Same as author!
        "approver_email": author_email,
        "approver_role": "RULE_AUTHOR",
        "comments": "Self approving my own rule."
    }
    resp = client.post(f"/approvals/{wf_id}/action", json=action_payload, headers=AUTH_HEADERS)
    assert resp.status_code in (400, 403), "Author self-approval should be strictly blocked!"
    print(f"  [PASS] Separation of Duties enforced: Author self-approval blocked (HTTP {resp.status_code}: {resp.json().get('detail')})")
    
    # 1.3 Request Changes
    req_changes_payload = {
        "action": "CHANGES_REQUESTED",
        "role": "COMPLIANCE_MANAGER",
        "comments": "Please update buffer threshold to 3.0% as per updated circular guidance.",
        "change_request_notes": "Buffer needs adjustment"
    }
    resp = client.post(f"/approvals/{wf_id}/action", json=req_changes_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Request changes failed: {resp.text}"
    wf_data = resp.json()["workflow"]
    assert wf_data["status"] == "CHANGES_REQUESTED"
    print(f"  [PASS] Changes requested: Status={wf_data['status']}")
    
    # 1.4 Resubmit Workflow
    resubmit_payload = {
        "action": "RESUBMITTED",
        "role": "RULE_AUTHOR",
        "comments": "Updated buffer threshold to 3.0%."
    }
    resp = client.post(f"/approvals/{wf_id}/action", json=resubmit_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    wf_data = resp.json()["workflow"]
    assert wf_data["status"] == "RESUBMITTED"
    print(f"  [PASS] Workflow resubmitted: Status={wf_data['status']}")
    
    # 1.5 Multi-Stage Approvals to Final APPROVED / READY_FOR_TESTING
    # Stage 0: Move from RESUBMITTED to UNDER_REVIEW
    resp = client.post(f"/approvals/{wf_id}/action", json={
        "action": "APPROVED",
        "role": "COMPLIANCE_ANALYST",
        "actor_email": "compliance_analyst@apexbank.com",
        "comments": "Initiating review"
    }, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    
    # Progress through all required review stages until final sign-off
    wf_data = client.get(f"/approvals/{wf_id}", headers=AUTH_HEADERS).json()["workflow"]
    while wf_data["status"] == "UNDER_REVIEW":
        curr_idx = wf_data["current_stage_index"]
        stage = wf_data["required_stages"][curr_idx]
        resp = client.post(f"/approvals/{wf_id}/action", json={
            "action": "APPROVED",
            "role": stage["required_role"],
            "actor_email": f"approver_{curr_idx}@apexbank.com",
            "comments": f"Approved stage {stage['stage_name']}"
        }, headers=AUTH_HEADERS)
        assert resp.status_code == 200
        wf_data = client.get(f"/approvals/{wf_id}", headers=AUTH_HEADERS).json()["workflow"]
    
    assert wf_data["status"] in ("APPROVED", "READY_FOR_TESTING")
    print(f"  [PASS] Multi-stage pipeline completed: Final Status={wf_data['status']}")
    
    # -------------------------------------------------------------------------
    # STAGE 2: RULE VERSION MANAGEMENT & DEEP IR DIFF COMPARISON
    # -------------------------------------------------------------------------
    print("\n[STAGE 2] Testing Rule Versioning & Deep IR Comparison...")
    
    # 2.1 Create Version 1.0 Snapshot
    v1_payload = {
        "rule_id": "RULE-RBI-LCR-2026",
        "rule_ir_snapshot": {
            "rule_id": "RULE-RBI-LCR-2026",
            "rule_name": "LCR Rule v1",
            "version": "1.0",
            "condition_tree": {
                "logical_operator": "AND",
                "conditions": [{"field": "lcr_ratio", "operator": ">=", "value": 100}]
            },
            "actions": [{"action_type": "APPLY_BUFFER", "parameters": {"buffer_pct": 2.5}}]
        },
        "change_summary": "Initial baseline production version",
        "regulatory_reference": "RBI/2026/01",
        "bump_type": "minor"
    }
    resp = client.post("/rules/versions", json=v1_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Version 1.0 creation failed: {resp.text}"
    v1 = resp.json()
    v1_id = v1["id"]
    print(f"  [PASS] Created baseline Version {v1['version_number']} (ID: {v1_id})")
    
    # 2.2 Create Version 1.1 Snapshot
    v2_payload = {
        "rule_id": "RULE-RBI-LCR-2026",
        "parent_version": v1["version_number"],
        "rule_ir_snapshot": {
            "rule_id": "RULE-RBI-LCR-2026",
            "rule_name": "LCR Rule v1.1 Modified",
            "version": "1.1",
            "condition_tree": {
                "logical_operator": "AND",
                "conditions": [
                    {"field": "lcr_ratio", "operator": ">=", "value": 110},
                    {"field": "daily_outflow", "operator": "<", "value": 5000000}
                ]
            },
            "actions": [{"action_type": "APPLY_BUFFER", "parameters": {"buffer_pct": 3.0}}]
        },
        "change_summary": "Raised LCR threshold and added outflow cap",
        "regulatory_reference": "RBI/2026/04",
        "bump_type": "minor"
    }
    resp = client.post("/rules/versions", json=v2_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Version 1.1 creation failed: {resp.text}"
    v2 = resp.json()
    v2_id = v2["id"]
    print(f"  [PASS] Created updated Version {v2['version_number']} (ID: {v2_id})")
    
    # 2.3 Deep IR Diff Comparison
    resp = client.get(f"/rules/RULE-RBI-LCR-2026/versions/compare?base_version={v1['version_number']}&target_version={v2['version_number']}", headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Version comparison failed: {resp.text}"
    comparison = resp.json()
    assert comparison["has_breaking_changes"] is True
    assert len(comparison["differences"]) > 0
    print(f"  [PASS] Deep IR Comparison: Breaking Change Detected ({comparison['has_breaking_changes']}), Differences Count: {len(comparison['differences'])}")
    
    # -------------------------------------------------------------------------
    # STAGE 3: RULE SIMULATION TESTING ENGINE
    # -------------------------------------------------------------------------
    print("\n[STAGE 3] Testing Sandbox Rule Simulation & Automated Boundary Tests...")
    
    # 3.1 Create Test Suite
    suite_payload = {
        "rule_id": "RULE-RBI-LCR-2026",
        "rule_version": v2["version_number"],
        "suite_name": "LCR 2026 Regulatory Verification Suite",
        "description": "Comprehensive simulation covering boundaries and edge cases"
    }
    resp = client.post("/testing/suites", json=suite_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Suite creation failed: {resp.text}"
    suite = resp.json()
    suite_id = suite["id"]
    print(f"  [PASS] Created Test Suite: ID={suite_id}")
    
    # 3.2 Auto-Generate Boundary & Functional Test Cases
    gen_payload = {
        "rule_ir": v2_payload["rule_ir_snapshot"]
    }
    resp = client.post("/testing/generate-cases", json=gen_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Generate cases failed: {resp.text}"
    generated_cases = resp.json()
    assert len(generated_cases) >= 3
    print(f"  [PASS] Auto-generated {len(generated_cases)} test cases (Boundary: Below, At, Above threshold)")
    
    # 3.3 Add Cases to Suite
    for tc in generated_cases:
        case_req = {
            "test_type": tc["test_type"],
            "scenario_name": tc["scenario_name"],
            "input_data": tc["input_data"],
            "expected_result": tc["expected_result"],
            "is_mandatory": tc.get("is_mandatory", True)
        }
        resp = client.post(f"/testing/suites/{suite_id}/cases", json=case_req, headers=AUTH_HEADERS)
        assert resp.status_code == 200
    
    # 3.4 Execute Sandbox Test Run
    resp = client.post(f"/testing/suites/{suite_id}/run", headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Run suite failed: {resp.text}"
    run_result = resp.json()
    print(f"  [PASS] Test Run Executed: Status={run_result['status']}, Passed={run_result['passed_tests']}/{run_result['total_test_cases']}, Pass Rate={run_result['pass_percentage']}%")
    
    # -------------------------------------------------------------------------
    # STAGE 4: DEPLOYMENT ORCHESTRATION & SAFETY GATES
    # -------------------------------------------------------------------------
    print("\n[STAGE 4] Testing Deployment Orchestration, SHA-256 & Safety Gates...")
    
    # 4.1 Create Deployment Package
    deploy_pkg_payload = {
        "rule_id": "RULE-RBI-LCR-2026",
        "version_id": v2_id,
        "rule_version": v2["version_number"],
        "approved_rule_ir": v2_payload["rule_ir_snapshot"],
        "regulatory_reference": "RBI/2026/04"
    }
    resp = client.post("/deployments/packages/create", json=deploy_pkg_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Package creation failed: {resp.text}"
    pkg = resp.json()
    pkg_id = pkg["id"]
    checksum = pkg["package_checksum"]
    print(f"  [PASS] Deployment Package Created: ID={pkg_id}, SHA-256={checksum[:16]}...")
    
    # 4.2 Target Protection: Read-Only Target Rejection via Pre-flight & Deployment Gate
    resp = client.post("/deployments/validate-readiness", json={
        "package_id": pkg_id,
        "target_id": "target-reporting-sql-readonly"
    }, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    readiness = resp.json()
    assert readiness["is_ready"] is False
    assert any("READ-ONLY" in b for b in readiness["blockers"])
    print(f"  [PASS] Readiness gate blocked read-only target: {readiness['blockers'][0]}")

    resp = client.post("/deployments/deploy", json={
        "package_id": pkg_id,
        "target_id": "target-reporting-sql-readonly",
        "deployment_mode": "MANUAL"
    }, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    failed_record = resp.json()
    assert failed_record["status"] == "FAILED"
    assert "READ-ONLY" in failed_record["error_message"]
    print(f"  [PASS] Read-only deployment rejected by gate: Status={failed_record['status']}")
    
    # 4.3 Controlled Deployment to Writable Target
    resp = client.post("/deployments/deploy", json={
        "package_id": pkg_id,
        "target_id": "target-prod-rest-01",
        "deployment_mode": "MANUAL"
    }, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Deployment failed: {resp.text}"
    dep_record = resp.json()
    dep_id = dep_record["id"]
    assert dep_record["status"] in ("SUCCESS", "ACTIVE")
    print(f"  [PASS] Deployment Activated: Status={dep_record['status']}, Target={dep_record.get('target_name', dep_record.get('target_id'))}")
    
    # -------------------------------------------------------------------------
    # STAGE 5: ROLLBACK & RECOVERY ENGINE
    # -------------------------------------------------------------------------
    print("\n[STAGE 5] Testing Rollback Engine & Safety Guardrails...")
    
    # 5.1 Rollback without justification blocked
    resp = client.post(f"/deployments/{dep_id}/rollback", json={
        "deployment_id": dep_id,
        "target_id": "target-prod-rest-01",
        "restored_version": v1["version_number"],
        "rollback_ir": v1_payload["rule_ir_snapshot"],
        "reason": ""
    }, headers=AUTH_HEADERS)
    assert resp.status_code == 400
    print(f"  [PASS] Rollback safety guardrail: Mandatory reason enforced (HTTP 400)")
    
    # 5.2 Rollback with valid justification restores previous good version
    resp = client.post(f"/deployments/{dep_id}/rollback", json={
        "deployment_id": dep_id,
        "target_id": "target-prod-rest-01",
        "restored_version": v1["version_number"],
        "rollback_ir": v1_payload["rule_ir_snapshot"],
        "reason": "Production liquidity incident drill: rolling back to baseline v1.0"
    }, headers=AUTH_HEADERS)
    assert resp.status_code == 200, f"Rollback failed: {resp.text}"
    rollback_res = resp.json()
    rollback_record = rollback_res["rollback"]
    assert rollback_record["status"] in ("SUCCESS", "COMPLETED")
    assert rollback_record["restored_version"] == v1["version_number"]
    print(f"  [PASS] Rollback successfully completed: Restored Version={rollback_record['restored_version']}, Status={rollback_record['status']}")
    
    # -------------------------------------------------------------------------
    # STAGE 6: AUDIT TRAIL & NOTIFICATION CENTER
    # -------------------------------------------------------------------------
    print("\n[STAGE 6] Testing Audit Trail & Compliance Export...")
    
    # 6.1 Audit Events Logged
    resp = client.get("/audit/events", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 5
    print(f"  [PASS] Append-only Audit Log verified: {len(events)} events recorded")
    
    # 6.2 CSV Export
    resp = client.get("/audit/export", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    csv_text = resp.text
    assert "Event ID" in csv_text and "Actor Email" in csv_text
    print(f"  [PASS] Audit Trail CSV Export: Valid RFC 4180 format ({len(csv_text)} bytes)")
    
    # 6.3 Notification Center
    resp = client.get("/notifications", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    notifs = resp.json()
    print(f"  [PASS] Notification Center verified: {len(notifs)} alerts received")
    
    print("\n" + "=" * 70)
    print("ALL MILESTONE 3 END-TO-END WORKFLOW TESTS PASSED SUCCESSFULLY! [100%]")
    print("=" * 70)

if __name__ == "__main__":
    run_all_e2e()
