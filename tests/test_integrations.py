import pytest
from fastapi.testclient import TestClient

from cidan.api import app
from cidan.services.integration_service import IntegrationService


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    monkeypatch.setenv("CIDAN_ACCESS_TOKEN", "test-token-cidan-2026")
    IntegrationService.reset_registry()


client = TestClient(app, headers={"Authorization": "Bearer test-token-cidan-2026"})
unauthenticated_client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Authentication Mandatory For All Endpoints (Requirement 4)
# ---------------------------------------------------------------------------

def test_authentication_mandatory_for_all_endpoints():
    endpoints = ("/integrations/verify", "/integrations/inspect-schema", "/integrations/fetch-rules")
    for endpoint in endpoints:
        res = unauthenticated_client.post(endpoint, json={"source_id": "src-auth-test", "source_type": "SQL"})
        assert res.status_code == 401, f"{endpoint} should reject requests without token"
        assert res.json()["detail"] == "A valid bearer access token is required."


# ---------------------------------------------------------------------------
# 2. Precondition Verification Required (Requirement 6)
# ---------------------------------------------------------------------------

def test_inspect_schema_requires_prior_verification():
    res = client.post(
        "/integrations/inspect-schema",
        json={
            "source_id": "unverified-src-01",
            "source_type": "POSTGRESQL",
            "bank_id": "apex-bank-01",
        },
    )
    assert res.status_code == 412
    assert "has not been successfully verified" in res.json()["detail"]


def test_fetch_rules_requires_prior_verification():
    res = client.post(
        "/integrations/fetch-rules",
        json={
            "source_id": "unverified-src-02",
            "source_type": "POSTGRESQL",
            "bank_id": "apex-bank-01",
        },
    )
    assert res.status_code == 412
    assert "has not been successfully verified" in res.json()["detail"]


# ---------------------------------------------------------------------------
# 3. Real PostgreSQL Database Integration Tests (Requirement 7)
# ---------------------------------------------------------------------------

def test_real_postgresql_connection_verification():
    """Tests live connection to real local PostgreSQL database using authorized credentials."""
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-pg-live",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "localhost",
                "port": 5432,
                "database_name": "postgres",
                "service_account": "postgres",
                "password": "3513",
                "schema": "compliance",
                "table_or_collection": "banking_rules",
            },
            "credential_ref": "vault://tokens/pg-auth-token",
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["details"]["authenticated"] is True
    assert "PostgreSQL" in data["details"]["db_version"]
    assert data["error"] is None


def test_real_postgresql_inspect_schema_zero_fabricated_data():
    """Tests real schema inspection queries information_schema from actual database."""
    # First verify source
    verify_res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-pg-inspect",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "localhost",
                "port": 5432,
                "database_name": "postgres",
                "service_account": "postgres",
                "password": "3513",
                "schema": "compliance",
                "table_or_collection": "banking_rules",
            },
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert verify_res.json()["status"] == "SUCCESS"

    # Now inspect schema
    res = client.post(
        "/integrations/inspect-schema",
        json={
            "source_id": "src-pg-inspect",
            "source_type": "POSTGRESQL",
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["source_type"] == "POSTGRESQL"
    assert data["schema_name"] == "compliance"
    assert "banking_rules" in data["tables"]
    # Check that real column types were retrieved from live information_schema
    col_names = [c["name"] for c in data["columns"]]
    assert "rule_code" in col_names
    assert "rule_content" in col_names
    assert "created_at" in col_names
    assert data["metadata"]["live_inspected"] is True


def test_real_postgresql_fetch_rules_zero_fabricated_data():
    """Queries real rows from PostgreSQL; never returns mock or sample catalog data."""
    # Verify source first
    verify_res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-pg-rules",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "localhost",
                "port": 5432,
                "database_name": "postgres",
                "service_account": "postgres",
                "password": "3513",
                "schema": "compliance",
                "table_or_collection": "banking_rules",
            },
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert verify_res.json()["status"] == "SUCCESS"

    # Fetch live rules
    res = client.post(
        "/integrations/fetch-rules",
        json={
            "source_id": "src-pg-rules",
            "source_type": "POSTGRESQL",
            "limit": 10,
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) == 2  # apex-bank-01 has exactly 2 rules in the real database
    codes = [r["rule_code"] for r in rules]
    assert "RULE-KYC-REAL" in codes
    assert "RULE-AML-REAL" in codes
    # Verify exact contents from PostgreSQL
    kyc_rule = next(r for r in rules if r["rule_code"] == "RULE-KYC-REAL")
    assert kyc_rule["rule_title"] == "Real PostgreSQL KYC Policy"
    assert "Mandatory Aadhaar/PAN" in kyc_rule["rule_content"]


# ---------------------------------------------------------------------------
# 4. Multi-Tenant Isolation & Cross-Bank Access Denial (Requirements 10 & 11)
# ---------------------------------------------------------------------------

def test_cross_bank_access_denial_in_fetch_rules():
    """Verifies that an authorized bank cannot query another bank's integration source."""
    # Source registered and verified for apex-bank-01
    verify_res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-apex-tenant",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "localhost",
                "port": 5432,
                "database_name": "postgres",
                "service_account": "postgres",
                "password": "3513",
                "schema": "compliance",
                "table_or_collection": "banking_rules",
            },
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert verify_res.json()["status"] == "SUCCESS"

    # Request attempting to pass a different bank_id is strictly denied
    res = client.post(
        "/integrations/fetch-rules",
        json={
            "source_id": "src-apex-tenant",
            "source_type": "POSTGRESQL",
            "bank_id": "unauthorized-rogue-bank",
            "allow_local": True,
        },
    )
    assert res.status_code == 403
    assert "User is authorized for bank" in res.json()["detail"] or "Cross-bank" in res.json()["detail"]


def test_tenant_isolation_filters_out_other_banks_rules():
    """Confirms rule-pg-003 belonging to 'other-bank-99' is excluded for 'apex-bank-01'."""
    verify_res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-filter-check",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "localhost",
                "port": 5432,
                "database_name": "postgres",
                "service_account": "postgres",
                "password": "3513",
                "schema": "compliance",
                "table_or_collection": "banking_rules",
            },
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert verify_res.json()["status"] == "SUCCESS"

    res = client.post(
        "/integrations/fetch-rules",
        json={
            "source_id": "src-filter-check",
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert res.status_code == 200
    rule_ids = [r["id"] for r in res.json()]
    assert "rule-pg-001" in rule_ids
    assert "rule-pg-002" in rule_ids
    assert "rule-pg-003" not in rule_ids  # Private other-bank rule is completely hidden


# ---------------------------------------------------------------------------
# 5. Real REST Test Endpoint (Requirement 8)
# ---------------------------------------------------------------------------

def test_real_rest_connectivity():
    """Tests real HTTP connectivity against live endpoint."""
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-real-rest",
            "source_type": "REST_API",
            "config_metadata": {
                "base_url": "https://httpbin.org/get",
                "endpoint": "",
            },
            "bank_id": "apex-bank-01",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["details"]["http_status"] == 200
    assert data["response_time_ms"] > 0


# ---------------------------------------------------------------------------
# 6. Unreachable Sources Error Handling (Requirement 9)
# ---------------------------------------------------------------------------

def test_unreachable_sql_source_returns_clear_failure_not_sample_records():
    """Unreachable sources return clean failure; NEVER fabricated data."""
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-unreachable",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "203.0.113.1",  # Test network non-routable IP
                "port": 5432,
                "database_name": "dead_db",
                "service_account": "user",
                "password": "pwd",
            },
            "bank_id": "apex-bank-01",
            "allow_local": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FAILED"
    assert data["sample_rules"] == []
    assert data["sample_data"] == []
    assert data["error"] is not None


# ---------------------------------------------------------------------------
# 7. Credential Protection & Masking (Requirement 12)
# ---------------------------------------------------------------------------

def test_credentials_never_exposed_in_response():
    raw_password = "super_secret_cleartext_db_pass"
    vault_ref = "vault://tokens/live-database-ro"

    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-cred-leak-test",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "localhost",
                "port": 5432,
                "database_name": "postgres",
                "service_account": "postgres",
                "password": raw_password,
            },
            "credential_ref": vault_ref,
            "bank_id": "apex-bank-01",
        },
    )
    assert res.status_code == 200
    body = res.text
    assert raw_password not in body
    assert vault_ref not in body or "vault://***" in body
