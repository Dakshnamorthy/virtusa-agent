import pytest
from pydantic import ValidationError

from cidan.models import RuleProposal
from cidan.rule_engine import evaluate, matches, validate_rule


def rule(operator="gt", value=80_000):
    return RuleProposal(
        rule_id="demo-rule", version=1, business_purpose="Synthetic threshold test",
        source_obligation_ids=["OBL-1"], description="Flag amounts above demo threshold.",
        trigger_conditions=[{"field": "amount", "operator": operator, "value": value}],
        required_inputs=["transaction_id", "amount"], decision_outcomes=["flag review"],
        validation_criteria=["Exercise the amount boundary."],
        rollback_considerations="Restore the prior local rule version.",
        supporting_citations=[{
            "document_id": "doc", "filename": "circular.pdf",
            "document_type": "circular", "page": 1,
            "excerpt": "Synthetic amount threshold", "chunk_id": "chunk",
        }],
        action="flag_review",
    ).model_dump(mode="json")


@pytest.mark.parametrize(
    ("amount", "expected"),
    [(79_999, False), (80_000, False), (80_001, True)],
)
def test_synthetic_threshold_boundary(amount, expected):
    assert matches(rule(), {"transaction_id": "t1", "amount": amount}) is expected


def test_rejects_unsupported_operator_and_field():
    with pytest.raises(ValidationError):
        validate_rule(rule(operator="contains"))
    bad_field = rule()
    bad_field["trigger_conditions"][0]["field"] = "account_balance"
    with pytest.raises(ValidationError):
        validate_rule(bad_field)


def test_rejects_coercion_of_rule_values():
    bad_value = rule()
    bad_value["trigger_conditions"][0]["value"] = "80000"
    with pytest.raises(ValidationError):
        validate_rule(bad_value)


def test_rejects_missing_values_invalid_types_and_out_of_range_values():
    with pytest.raises(ValueError, match="Missing transaction field"):
        evaluate(rule(), {"transaction_id": "t1"})
    with pytest.raises(TypeError):
        evaluate(rule(), {"transaction_id": "t1", "amount": "80001"})
    with pytest.raises(ValueError, match="permitted range"):
        evaluate(rule(), {"transaction_id": "t1", "amount": -1})


def test_rejects_llm_or_expression_payloads():
    unsafe = rule()
    unsafe["expression"] = "__import__('os').system('whoami')"
    with pytest.raises(ValidationError):
        validate_rule(unsafe)
