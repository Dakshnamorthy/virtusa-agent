"""
Tests for CIDAN Milestone 2: AI Rule Analysis, Universal Rule IR, Delta Analysis & Validation Engine
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from cidan.api import app
from cidan.config import get_settings
from cidan.services.delta_analysis_service import (
    DeltaAnalysisResult,
    RuleDelta,
    run_delta_analysis,
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
from cidan.services.rule_validation_service import validate_rule_ir


@pytest.fixture
def auth_headers(monkeypatch):
    monkeypatch.setenv("CIDAN_ACCESS_TOKEN", "test-milestone-2-token")
    return {"Authorization": "Bearer test-milestone-2-token"}


@pytest.fixture
def client(auth_headers):
    return TestClient(app, headers=auth_headers)


# ============================================================================
# 1. UNIVERSAL RULE IR & NORMALIZATION TESTS
# ============================================================================

def test_normalize_to_rule_ir():
    raw_rule = {
        "rule_id": "TEST-RULE-001",
        "rule_name": "High Value Alert",
        "category": "AML",
        "condition_tree": {
            "operator": "AND",
            "conditions": [
                {"field": "transaction_amount", "operator": "gte", "value": 1000000, "unit": "INR"},
                {"field": "is_emergency", "operator": "eq", "value": False},
            ],
        },
        "actions": [
            {"action_type": "FLAG_REVIEW", "target": "transaction", "priority": 1}
        ],
    }
    rule_ir = normalize_to_rule_ir(raw_rule)
    assert rule_ir.rule_id == "TEST-RULE-001"
    assert rule_ir.category == "AML"
    assert len(rule_ir.condition_tree.conditions) == 2
    assert rule_ir.condition_tree.conditions[0].operator == "gte"
    assert rule_ir.actions[0].action_type == "FLAG_REVIEW"


def test_extract_rules_from_json():
    json_content = """[
        {
            "rule_id": "KYC-001",
            "rule_name": "PEP Mandatory CDD",
            "category": "KYC",
            "condition_tree": {
                "operator": "AND",
                "conditions": [
                    {"field": "is_pep", "operator": "eq", "value": true}
                ]
            },
            "actions": [{"action_type": "SECOND_REVIEW", "target": "customer_account"}]
        }
    ]"""
    rules = extract_rules_from_existing_content(json_content, "kyc_policy.json", "json", "apex-bank-01")
    assert len(rules) == 1
    assert rules[0].rule_id == "KYC-001"
    assert rules[0].category == "KYC"
    assert rules[0].actions[0].action_type == "SECOND_REVIEW"


def test_extract_rules_from_sql():
    sql_content = """
    CREATE RULE rule_cash_limit AS ON INSERT TO transactions
    WHERE amount >= 1000000 DO INSTEAD NOTHING;
    """
    rules = extract_rules_from_existing_content(sql_content, "schema.sql", "sql", "apex-bank-01")
    assert len(rules) >= 1
    assert any("cash_limit" in r.rule_name.lower() or "sql" in r.rule_id.lower() for r in rules)


def test_extract_rules_from_text():
    text_content = (
        "1. Cash Transaction Rule: Mandatory reporting for all cash deposits exceeding INR 1,000,000 within 15 days.\n\n"
        "2. Cross-Border Wire: Requires dual officer review for transfers above USD 50,000."
    )
    rules = extract_rules_from_existing_content(text_content, "handbook.txt", "txt", "apex-bank-01")
    assert len(rules) == 2
    assert rules[0].category == "GENERAL" or rules[0].category == "AML"


# ============================================================================
# 2. CIRCULAR EXTRACTION & DELTA ANALYSIS TESTS
# ============================================================================

def test_extract_circular_obligations():
    circular = """
    RBI/2026/89 Circular on Enhanced Due Diligence
    Section 1. Applicability: All Commercial Banks shall comply with immediate effect.
    Section 2. Cash Reporting: Banks must report all cash transactions exceeding INR 500,000 within 7 days to FIU.
    Section 3. IT Cloud Security: Banks shall maintain immutable audit logs for a minimum of 180 days.
    """
    obligations = extract_obligations_from_circular(circular, "RBI/2026/89", "RBI", "circular.pdf", "apex-bank-01")
    assert len(obligations) >= 2
    cash_ob = next(o for o in obligations if "500,000" in o["requirement_text"] or "cash" in o["requirement_text"].lower())
    assert cash_ob["is_mandatory"] is True
    assert cash_ob["clause_id"].startswith("CL-")


def test_delta_analysis_classification():
    existing_rule = RuleIR(
        rule_id="EXIST-AML-01",
        rule_name="Cash Transaction Threshold",
        category="AML",
        condition_tree=ConditionTree(operator="AND", conditions=[
            ConditionNode(field="transaction_amount", operator="gte", value=1000000, unit="INR"),
            ConditionNode(field="reporting_deadline_days", operator="lte", value=15, unit="DAYS"),
        ]),
        actions=[ActionNode(action_type="FLAG_REVIEW", target="transaction")],
    )

    circular = """
    Clause 1. Mandatory Threshold Update: Banks shall monitor and report all cash transactions exceeding INR 500,000 within 7 days.
    Clause 2. Cloud Data Residency: Banks must store all primary cryptographic key material within domestic data centers.
    """
    obligations = extract_obligations_from_circular(circular, "RBI/2026/90", "RBI", "circ.pdf", "apex-bank-01")

    result = run_delta_analysis(
        bank_id="apex-bank-01",
        existing_rules=[existing_rule],
        circular_obligations=obligations,
        circular_number="RBI/2026/90",
    )

    assert result.status == "COMPLETED"
    assert result.total_rules >= 2
    # Cash threshold should be MODIFICATION (lowered from 1,000,000 to 500,000)
    mod_deltas = [d for d in result.deltas if d.classification == "MODIFICATION"]
    assert len(mod_deltas) >= 1
    mod_delta = mod_deltas[0]
    assert mod_delta.identified_differences[0].field == "transaction_amount"
    assert mod_delta.identified_differences[0].proposed_value == 500000.0
    assert mod_delta.reason != ""
    assert mod_delta.impact_assessment != ""

    # Cloud residency should be ADDITION (no prior existing rule)
    add_deltas = [d for d in result.deltas if d.classification == "ADDITION"]
    assert len(add_deltas) >= 1


# ============================================================================
# 3. RULE VALIDATION ENGINE TESTS
# ============================================================================

def test_rule_validation_contradiction():
    invalid_rule = RuleIR(
        rule_id="RULE-BAD-01",
        rule_name="Contradictory Rule",
        category="AML",
        condition_tree=ConditionTree(operator="AND", conditions=[
            ConditionNode(field="amount", operator="gt", value=500000),
            ConditionNode(field="amount", operator="lt", value=200000),
        ]),
        actions=[ActionNode(action_type="FLAG_REVIEW", target="transaction")],
    )
    findings = validate_rule_ir(invalid_rule)
    assert any(f.rule_code == "LOGIC_CONTRADICTION" and f.severity == "ERROR" for f in findings)


def test_rule_validation_negative_amount():
    neg_rule = RuleIR(
        rule_id="RULE-NEG-01",
        rule_name="Negative Amount Rule",
        category="LENDING",
        condition_tree=ConditionTree(operator="AND", conditions=[
            ConditionNode(field="transaction_amount", operator="gte", value=-500),
        ]),
        actions=[ActionNode(action_type="FLAG_REVIEW", target="transaction")],
    )
    findings = validate_rule_ir(neg_rule)
    assert any(f.rule_code == "LOGIC_NEGATIVE_AMOUNT" and f.severity == "ERROR" for f in findings)


# ============================================================================
# 4. FASTAPI ENDPOINT TESTS
# ============================================================================

def test_api_extract_existing_rules(client):
    res = client.post(
        "/rules/extract-existing",
        json={"content": "Rule 1: All remittances above INR 500,000 need second approval.", "filename": "policy.txt", "file_format": "txt"},
    )
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["rule_name"] != ""


def test_api_extract_circular(client):
    res = client.post(
        "/rules/extract-circular",
        json={
            "circular_text": "Clause 1. Banks must maintain CRAR at or above 11.5% with effect from 1st April 2026.",
            "circular_number": "RBI/2026/101",
            "authority": "RBI",
        },
    )
    assert res.status_code == 200
    obligations = res.json()
    assert len(obligations) >= 1
    assert obligations[0]["circular_number"] == "RBI/2026/101"


def test_api_analyze_deltas(client):
    res = client.post(
        "/deltas/analyze",
        json={
            "analysis_name": "Test Delta Run",
            "circular_number": "RBI/2026/TEST",
            "circular_text": "Clause 1. Mandatory reporting of high value transactions exceeding INR 500,000 within 7 days.",
        },
    )
    assert res.status_code == 200
    result = res.json()
    assert result["status"] == "COMPLETED"
    assert result["total_rules"] >= 1
    assert len(result["deltas"]) >= 1


def test_api_save_mapping(client):
    # First run an analysis to create deltas
    analyze_res = client.post(
        "/deltas/analyze",
        json={
            "analysis_name": "Mapping Test Run",
            "circular_number": "RBI/2026/MAPPING",
            "circular_text": "Clause 1. New Cyber Incident Reporting within 2 hours.",
        },
    )
    delta_id = analyze_res.json()["deltas"][0]["id"]

    save_res = client.post(
        "/deltas/mappings/save",
        json={
            "delta_id": delta_id,
            "decision": "ACCEPTED",
            "user_notes": "Reviewed and accepted by Chief Compliance Officer.",
        },
    )
    assert save_res.status_code == 200
    assert save_res.json()["status"] == "SUCCESS"


def test_api_validate_rule(client):
    rule = {
        "rule_id": "TEST-VALID-01",
        "rule_name": "Valid Rule Test",
        "category": "AML",
        "condition_tree": {
            "operator": "AND",
            "conditions": [{"field": "transaction_amount", "operator": "gte", "value": 100000}],
        },
        "actions": [{"action_type": "FLAG_REVIEW", "target": "transaction"}],
        "traceability": {"circular_number": "RBI/2026/TEST"},
    }
    res = client.post("/rules/validate", json={"rule": rule})
    assert res.status_code == 200
    findings = res.json()
    assert any(f["severity"] == "INFO" for f in findings)


def test_api_cross_bank_denial(client):
    # Authenticated user is for apex-bank-01; supplying another bank_id must return 403 Forbidden
    res = client.post(
        "/rules/extract-existing",
        json={"content": "Some rule", "bank_id": "other-bank-99"},
    )
    assert res.status_code == 403
    assert "Cross-bank access denied" in res.json()["detail"]
