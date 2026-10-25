from collections.abc import Callable
from typing import Any

from cidan.models import RuleProposal

ALLOWED_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
}
FIELD_TYPES = {
    "amount": (int, float),
    "retention_days": (int,),
    "is_emergency": (bool,),
}
MAX_AMOUNT = 1_000_000_000_000
MAX_RETENTION_DAYS = 36_500


def validate_rule(rule: dict[str, Any]) -> RuleProposal:
    proposal = RuleProposal.model_validate(rule)
    if proposal.status not in {"draft", "validated", "approved_for_export"}:
        raise ValueError("Unsupported rule status.")
    allowed_inputs = {
        "transaction_id", "amount", "retention_days", "is_emergency", "exception_reason"
    }
    if not set(proposal.required_inputs) <= allowed_inputs:
        raise ValueError("Rule declares an unsupported required input.")
    condition_fields = {condition.field for condition in proposal.trigger_conditions}
    required = condition_fields | {"transaction_id"}
    if proposal.action == "require_exception_reason":
        required.add("exception_reason")
        if "is_emergency" not in condition_fields:
            raise ValueError("Exception-reason rules must be conditioned on is_emergency.")
    if not required <= set(proposal.required_inputs):
        raise ValueError("Rule required_inputs omits a field used by its conditions or action.")
    expected_fields = {
        "flag_review": "amount",
        "second_review": "amount",
        "retention_gap": "retention_days",
    }
    if proposal.action in expected_fields and not condition_fields <= {expected_fields[proposal.action]}:
        raise ValueError("Rule action is incompatible with its condition fields.")
    for condition in proposal.trigger_conditions:
        if condition.field not in FIELD_TYPES or condition.operator not in ALLOWED_OPS:
            raise ValueError("Unsupported rule field or operator.")
        value = condition.value
        expected_types = FIELD_TYPES[condition.field]
        if isinstance(value, bool) and condition.field != "is_emergency":
            raise TypeError(f"Boolean value is not valid for {condition.field}.")
        if not isinstance(value, expected_types):
            raise TypeError(f"Invalid value type for {condition.field}.")
        if condition.field == "is_emergency" and condition.operator not in {"eq", "ne"}:
            raise ValueError("Boolean conditions support only eq and ne.")
        if condition.field == "amount" and not 0 <= value <= MAX_AMOUNT:
            raise ValueError("Amount threshold is outside the permitted range.")
        if condition.field == "retention_days" and not 0 <= value <= MAX_RETENTION_DAYS:
            raise ValueError("Retention threshold is outside the permitted range.")
    return proposal


def matches(rule: dict[str, Any], transaction: dict[str, Any]) -> bool:
    proposal = validate_rule(rule)
    outcomes: list[bool] = []
    for condition in proposal.trigger_conditions:
        if condition.field not in transaction:
            raise ValueError(f"Missing transaction field: {condition.field}")
        actual = transaction[condition.field]
        if isinstance(actual, bool) and condition.field != "is_emergency":
            raise TypeError(f"Invalid transaction type for {condition.field}.")
        if not isinstance(actual, FIELD_TYPES[condition.field]):
            raise TypeError(f"Invalid transaction type for {condition.field}.")
        if condition.field == "amount" and not 0 <= actual <= MAX_AMOUNT:
            raise ValueError("Transaction amount is outside the permitted range.")
        if condition.field == "retention_days" and not 0 <= actual <= MAX_RETENTION_DAYS:
            raise ValueError("Transaction retention_days is outside the permitted range.")
        outcomes.append(ALLOWED_OPS[condition.operator](actual, condition.value))
    return all(outcomes)


def evaluate(rule: dict[str, Any], transaction: dict[str, Any]) -> dict[str, Any]:
    proposal = validate_rule(rule)
    if not isinstance(transaction.get("transaction_id"), str):
        raise ValueError("A transaction_id string is required.")
    hit = matches(rule, transaction)
    if proposal.action == "require_exception_reason" and hit:
        reason = transaction.get("exception_reason")
        triggered = not isinstance(reason, str) or not reason.strip()
    else:
        triggered = hit
    return {
        "transaction_id": transaction["transaction_id"],
        "rule_id": proposal.rule_id,
        "triggered": triggered,
    }
