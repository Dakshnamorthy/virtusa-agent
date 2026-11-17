import pytest
from fastapi.testclient import TestClient

from cidan.api import app


@pytest.fixture(autouse=True)
def configure_test_access_token(monkeypatch):
    monkeypatch.setenv("CIDAN_ACCESS_TOKEN", "test-token-cidan-2026")


client = TestClient(app, headers={"Authorization": "Bearer test-token-cidan-2026"})
unauthenticated_client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Authentication & Tenant Authorization Tests
# ---------------------------------------------------------------------------

def test_integration_endpoints_require_authentication():
    for endpoint in ("/integrations/verify", "/integrations/inspect-schema", "/integrations/fetch-rules"):
        res = unauthenticated_client.post(endpoint, json={"source_id": "test-src", "source_type": "SQL"})
        assert res.status_code == 401, f"{endpoint} should require authentication"
        assert "detail" in res.json()


# ---------------------------------------------------------------------------
# 2. Connection Verification Tests: REST API & GraphQL
# ---------------------------------------------------------------------------

def test_verify_rest_api_missing_base_url():
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-rest-01",
            "source_type": "REST_API",
            "config_metadata": {},
            "bank_id": "apex-bank-01",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FAILED"
    assert "base_url is required" in data["error"]


def test_verify_rest_api_blocks_internal_hosts():
    for internal_host in ("http://localhost:8080/rules", "http://127.0.0.1:3000", "http://core.bank.internal"):
        res = client.post(
            "/integrations/verify",
            json={
                "source_id": "src-rest-internal",
                "source_type": "REST_API",
                "config_metadata": {"base_url": internal_host},
                "bank_id": "apex-bank-01",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "FAILED"
        assert "not directly routable" in data["error"] or "Internal host" in data["error"]


def test_verify_graphql_blocks_internal_hosts():
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-gql-01",
            "source_type": "GRAPHQL",
            "config_metadata": {"base_url": "http://10.0.1.5:4000/graphql"},
            "bank_id": "apex-bank-01",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FAILED"
    assert "Internal host" in data["error"]


# ---------------------------------------------------------------------------
# 3. Connection Verification Tests: SQL & NoSQL Databases
# ---------------------------------------------------------------------------

def test_verify_sql_validation_checks():
    # Missing host
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-sql-01",
            "source_type": "POSTGRESQL",
            "config_metadata": {"database_name": "cidan_db", "service_account": "cidan_reader"},
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "FAILED"
    assert "host address is required" in res.json()["error"]

    # Invalid port range
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-sql-02",
            "source_type": "ORACLE",
            "config_metadata": {
                "host": "oracle.cloud.bank",
                "port": 999999,
                "database_name": "ORCL",
                "service_account": "admin",
            },
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "FAILED"
    assert "Invalid port" in res.json()["error"]

    # Internal host protection
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-sql-03",
            "source_type": "MYSQL",
            "config_metadata": {
                "host": "192.168.1.100",
                "port": 3306,
                "database_name": "cidan_mysql",
                "service_account": "root",
            },
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "FAILED"
    assert "not directly reachable" in res.json()["error"]


def test_verify_nosql_validation_checks():
    # MongoDB validation
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-mongo-01",
            "source_type": "MONGODB",
            "config_metadata": {
                "host": "127.0.0.1",
                "port": 27017,
                "database_name": "rules_db",
            },
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "FAILED"
    assert "Internal host" in res.json()["error"]

    # Cassandra missing host
    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-cas-01",
            "source_type": "CASSANDRA",
            "config_metadata": {},
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "FAILED"
    assert "host address is required" in res.json()["error"]


# ---------------------------------------------------------------------------
# 4. Schema Inspection Tests
# ---------------------------------------------------------------------------

def test_inspect_schema_returns_structured_metadata():
    res = client.post(
        "/integrations/inspect-schema",
        json={
            "source_id": "src-inspect-01",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "schema": "compliance",
                "table_or_collection": "lending_rules",
            },
            "bank_id": "apex-bank-99",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["source_type"] == "POSTGRESQL"
    assert data["schema_name"] == "compliance"
    assert "lending_rules" in data["tables"]
    assert any(col["name"] == "rule_code" for col in data["columns"])
    assert any(col["name"] == "rule_content" for col in data["columns"])
    assert data["metadata"]["isolation_tenant"] == "apex-bank-99"


def test_inspect_schema_sanitizes_malicious_table_identifiers():
    res = client.post(
        "/integrations/inspect-schema",
        json={
            "source_id": "src-inspect-sqli",
            "source_type": "SQL",
            "config_metadata": {
                "schema": "public; DROP TABLE users;--",
                "table_or_collection": "rules; SHUTDOWN;--",
            },
        },
    )
    assert res.status_code == 200
    data = res.json()
    # Malicious injection strings are rejected and sanitized to safe defaults
    assert data["schema_name"] == "public"
    assert "compliance_rules" in data["tables"]


# ---------------------------------------------------------------------------
# 5. Read-Only Rule Retrieval Tests
# ---------------------------------------------------------------------------

def test_fetch_rules_respects_tenant_isolation_and_limit():
    res = client.post(
        "/integrations/fetch-rules",
        json={
            "source_id": "src-rules-01",
            "source_type": "POSTGRESQL",
            "limit": 3,
            "bank_id": "tenant-bank-alpha",
        },
    )
    assert res.status_code == 200
    rules = res.json()
    assert isinstance(rules, list)
    assert len(rules) == 3
    for rule in rules:
        assert rule["bank_id"] == "tenant-bank-alpha"
        assert rule["source_id"] == "src-rules-01"
        assert "rule_code" in rule
        assert "rule_title" in rule
        assert "rule_content" in rule


def test_fetch_rules_enforces_max_limit_bound():
    res = client.post(
        "/integrations/fetch-rules",
        json={
            "source_id": "src-rules-02",
            "source_type": "ORACLE",
            "limit": 99999,  # Attempting to request excessive limit
            "bank_id": "tenant-bank-beta",
        },
    )
    # Pydantic validation rejects limit > 50 with 422
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# 6. Credential Safety & Zero Leakage Tests
# ---------------------------------------------------------------------------

def test_verify_does_not_leak_credentials_in_response():
    raw_secret = "super_secret_db_password_12345"
    vault_ref = "vault://tokens/live-prod-ro-secret"

    res = client.post(
        "/integrations/verify",
        json={
            "source_id": "src-cred-check",
            "source_type": "POSTGRESQL",
            "config_metadata": {
                "host": "10.0.0.5",
                "port": 5432,
                "database_name": "core_bank",
                "service_account": "app_user",
                "password": raw_secret,
            },
            "credential_ref": vault_ref,
            "bank_id": "apex-bank-01",
        },
    )
    assert res.status_code == 200
    body_text = res.text
    assert raw_secret not in body_text, "Raw database password leaked in response body!"
    assert vault_ref not in body_text or "vault://***" in body_text, "Vault reference exposed without masking!"
