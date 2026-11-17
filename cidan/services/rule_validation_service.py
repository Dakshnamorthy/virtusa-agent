"""
CIDAN Rule Validation Engine
Milestone 2 - Structural, Logical & Regulatory Multi-Tier Validation
"""
from __future__ import annotations

import uuid
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from cidan.services.rule_ir_service import (
    ConditionNode,
    ConditionTree,
    RuleIR,
    normalize_to_rule_ir,
)


class ValidationFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: Optional[str] = None
    rule_ir_id: Optional[str] = None
    delta_id: Optional[str] = None
    validation_type: Literal["STRUCTURAL", "LOGICAL", "REGULATORY"]
    severity: Literal["ERROR", "WARNING", "INFO"]
    rule_code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


def _flatten_conditions(tree: ConditionTree) -> list[ConditionNode]:
    res: list[ConditionNode] = []
    for c in tree.conditions:
        if isinstance(c, ConditionNode):
            res.append(c)
        elif isinstance(c, ConditionTree):
            res.extend(_flatten_conditions(c))
        elif isinstance(c, dict):
            if "conditions" in c:
                res.extend(_flatten_conditions(ConditionTree(**c)))
            elif "field" in c and "operator" in c:
                res.append(ConditionNode(**c))
    return res


def validate_rule_ir(
    rule: RuleIR | dict[str, Any],
    delta_id: Optional[str] = None,
    bank_id: Optional[str] = None,
) -> list[ValidationFinding]:
    """
    Performs comprehensive structural, logical, and regulatory checks on a RuleIR.
    Returns a list of ValidationFinding objects with severity ERROR, WARNING, or INFO.
    """
    if isinstance(rule, dict):
        rule = normalize_to_rule_ir(rule)

    findings: list[ValidationFinding] = []
    r_id = rule.id or rule.rule_id

    # -------------------------------------------------------------
    # 1. STRUCTURAL VALIDATION
    # -------------------------------------------------------------
    if not rule.rule_id or len(rule.rule_id.strip()) < 3:
        findings.append(ValidationFinding(
            bank_id=bank_id,
            rule_ir_id=r_id,
            delta_id=delta_id,
            validation_type="STRUCTURAL",
            severity="ERROR",
            rule_code="STRUC_MISSING_ID",
            message="Rule ID is missing or too short.",
            details={"field": "rule_id"},
        ))

    if not rule.rule_name or len(rule.rule_name.strip()) < 3:
        findings.append(ValidationFinding(
            bank_id=bank_id,
            rule_ir_id=r_id,
            delta_id=delta_id,
            validation_type="STRUCTURAL",
            severity="ERROR",
            rule_code="STRUC_MISSING_NAME",
            message="Rule Name is required and must have at least 3 characters.",
            details={"field": "rule_name"},
        ))

    if not rule.actions:
        findings.append(ValidationFinding(
            bank_id=bank_id,
            rule_ir_id=r_id,
            delta_id=delta_id,
            validation_type="STRUCTURAL",
            severity="ERROR",
            rule_code="STRUC_NO_ACTIONS",
            message="Rule must declare at least one execution action.",
            details={"field": "actions"},
        ))

    flat_conditions = _flatten_conditions(rule.condition_tree)
    if not flat_conditions:
        findings.append(ValidationFinding(
            bank_id=bank_id,
            rule_ir_id=r_id,
            delta_id=delta_id,
            validation_type="STRUCTURAL",
            severity="WARNING",
            rule_code="STRUC_EMPTY_CONDITIONS",
            message="Rule has no trigger conditions defined; it may trigger unconditionally.",
            details={"condition_count": 0},
        ))

    for cond in flat_conditions:
        if not cond.field:
            findings.append(ValidationFinding(
                bank_id=bank_id,
                rule_ir_id=r_id,
                delta_id=delta_id,
                validation_type="STRUCTURAL",
                severity="ERROR",
                rule_code="STRUC_INVALID_CONDITION_FIELD",
                message="Condition is missing a target field name.",
                details={"condition": cond.model_dump()},
            ))
        if cond.operator not in ("gt", "gte", "lt", "lte", "eq", "ne", "in", "contains", "between"):
            findings.append(ValidationFinding(
                bank_id=bank_id,
                rule_ir_id=r_id,
                delta_id=delta_id,
                validation_type="STRUCTURAL",
                severity="ERROR",
                rule_code="STRUC_INVALID_OPERATOR",
                message=f"Condition operator '{cond.operator}' is unsupported.",
                details={"operator": cond.operator},
            ))

    # -------------------------------------------------------------
    # 2. LOGICAL VALIDATION
    # -------------------------------------------------------------
    # Check for contradictions: e.g. amount > X and amount < Y where X >= Y under AND
    if rule.condition_tree.operator == "AND" and len(flat_conditions) > 1:
        field_conds: dict[str, list[ConditionNode]] = {}
        for c in flat_conditions:
            field_conds.setdefault(c.field, []).append(c)

        for field_name, conds in field_conds.items():
            gt_val = next((c.value for c in conds if c.operator in ("gt", "gte") and isinstance(c.value, (int, float))), None)
            lt_val = next((c.value for c in conds if c.operator in ("lt", "lte") and isinstance(c.value, (int, float))), None)
            if gt_val is not None and lt_val is not None:
                if gt_val > lt_val:
                    findings.append(ValidationFinding(
                        bank_id=bank_id,
                        rule_ir_id=r_id,
                        delta_id=delta_id,
                        validation_type="LOGICAL",
                        severity="ERROR",
                        rule_code="LOGIC_CONTRADICTION",
                        message=f"Logical contradiction on field '{field_name}': threshold {gt_val} is greater than upper limit {lt_val} under AND operator.",
                        details={"field": field_name, "gt_threshold": gt_val, "lt_threshold": lt_val},
                    ))

            # Equality contradiction: status == 'A' AND status == 'B'
            eq_vals = [c.value for c in conds if c.operator == "eq"]
            if len(eq_vals) > 1 and len(set(eq_vals)) > 1:
                findings.append(ValidationFinding(
                    bank_id=bank_id,
                    rule_ir_id=r_id,
                    delta_id=delta_id,
                    validation_type="LOGICAL",
                    severity="ERROR",
                    rule_code="LOGIC_MUTEX_EQUALITY",
                    message=f"Mutual exclusivity contradiction on field '{field_name}': cannot equal both '{eq_vals[0]}' and '{eq_vals[1]}' under AND.",
                    details={"field": field_name, "values": eq_vals},
                ))

    # Range and sanity bounds
    for c in flat_conditions:
        if "amount" in c.field.lower() and isinstance(c.value, (int, float)):
            if c.value < 0:
                findings.append(ValidationFinding(
                    bank_id=bank_id,
                    rule_ir_id=r_id,
                    delta_id=delta_id,
                    validation_type="LOGICAL",
                    severity="ERROR",
                    rule_code="LOGIC_NEGATIVE_AMOUNT",
                    message=f"Negative financial amount threshold {c.value} is invalid.",
                    details={"field": c.field, "value": c.value},
                ))
            elif c.value > 100_000_000_000:
                findings.append(ValidationFinding(
                    bank_id=bank_id,
                    rule_ir_id=r_id,
                    delta_id=delta_id,
                    validation_type="LOGICAL",
                    severity="WARNING",
                    rule_code="LOGIC_EXCESSIVE_AMOUNT",
                    message=f"Amount threshold {c.value} is extraordinarily high (exceeds 100 Billion).",
                    details={"field": c.field, "value": c.value},
                ))

        if ("days" in c.field.lower() or "retention" in c.field.lower()) and isinstance(c.value, (int, float)):
            if c.value <= 0:
                findings.append(ValidationFinding(
                    bank_id=bank_id,
                    rule_ir_id=r_id,
                    delta_id=delta_id,
                    validation_type="LOGICAL",
                    severity="ERROR",
                    rule_code="LOGIC_ZERO_DAYS",
                    message=f"Deadline or retention days must be greater than zero, received {c.value}.",
                    details={"field": c.field, "value": c.value},
                ))

    # -------------------------------------------------------------
    # 3. REGULATORY VALIDATION
    # -------------------------------------------------------------
    # Traceability check
    if not rule.traceability or not (rule.traceability.get("circular_number") or rule.traceability.get("filename")):
        findings.append(ValidationFinding(
            bank_id=bank_id,
            rule_ir_id=r_id,
            delta_id=delta_id,
            validation_type="REGULATORY",
            severity="WARNING",
            rule_code="REG_UNTRACEABLE_RULE",
            message="Rule lacks regulatory circular or policy document traceability metadata.",
            details={"traceability": rule.traceability},
        ))

    # High-Risk category check
    if rule.category in ("AML", "SANCTIONS", "KYC"):
        # AML and SANCTIONS should have ESCALATE, BLOCK, or FLAG_REVIEW
        actions = [a.action_type for a in rule.actions]
        if not any(a in ("BLOCK", "ESCALATE", "FLAG_REVIEW", "SECOND_REVIEW") for a in actions):
            findings.append(ValidationFinding(
                bank_id=bank_id,
                rule_ir_id=r_id,
                delta_id=delta_id,
                validation_type="REGULATORY",
                severity="WARNING",
                rule_code="REG_LOW_SEVERITY_ACTION",
                message=f"Rule in high-risk category '{rule.category}' has mild actions {actions}; regulatory compliance usually mandates review or block.",
                details={"category": rule.category, "actions": actions},
            ))

    # If all clean, add an INFO validation finding
    if not any(f.severity in ("ERROR", "WARNING") for f in findings):
        findings.append(ValidationFinding(
            bank_id=bank_id,
            rule_ir_id=r_id,
            delta_id=delta_id,
            validation_type="STRUCTURAL",
            severity="INFO",
            rule_code="RULE_VERIFIED_VALID",
            message="Rule passed all structural, logical, and regulatory validation checks.",
            details={"rule_id": rule.rule_id},
        ))

    return findings
