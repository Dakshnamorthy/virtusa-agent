"""
CIDAN AI Delta Analysis Service
Milestone 2 - AI-Powered Rule Comparison, 6-Category Classification & Explainable AI Diff
"""
from __future__ import annotations

import copy
import uuid
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from cidan.services.rule_ir_service import (
    ActionNode,
    ConditionNode,
    ConditionTree,
    RuleIR,
    normalize_to_rule_ir,
)


class DiffItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    field: str
    previous_value: Any
    proposed_value: Any
    diff_type: Literal[
        "threshold_lowered",
        "threshold_raised",
        "threshold_changed",
        "operator_changed",
        "action_escalated",
        "action_relaxed",
        "condition_added",
        "scope_expanded",
        "wording_clarification",
    ]


class RuleDelta(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_id: Optional[str] = None
    bank_id: Optional[str] = None
    classification: Literal[
        "ADDITION",
        "MODIFICATION",
        "REMOVAL",
        "CLARIFICATION",
        "NO_IMPACT",
        "MANUAL_REVIEW_REQUIRED",
    ]
    category: str = "GENERAL"
    rule_name: str
    previous_rule_id: Optional[str] = None
    regulatory_obligation_id: Optional[str] = None
    previous_rule_representation: Optional[dict[str, Any]] = None
    new_requirement_representation: Optional[dict[str, Any]] = None
    identified_differences: list[DiffItem] = Field(default_factory=list)
    proposed_change: dict[str, Any] = Field(default_factory=dict)
    reason: str
    impact_assessment: str
    confidence_score: float = Field(default=0.95, ge=0.0, le=1.0)
    evidence_sources: list[dict[str, Any]] = Field(default_factory=list)
    review_status: Literal["PENDING", "ACCEPTED", "MODIFIED", "REJECTED", "NEEDS_REVIEW"] = "PENDING"
    created_at: Optional[str] = None


class DeltaAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: Optional[str] = None
    analysis_name: str
    circular_id: Optional[str] = None
    circular_number: Optional[str] = None
    status: Literal["PROCESSING", "COMPLETED", "FAILED"] = "COMPLETED"
    total_rules: int = 0
    additions_count: int = 0
    modifications_count: int = 0
    removals_count: int = 0
    clarifications_count: int = 0
    no_impact_count: int = 0
    manual_review_count: int = 0
    summary: str = ""
    deltas: list[RuleDelta] = Field(default_factory=list)


def _extract_leaf_conditions(tree: ConditionTree) -> list[ConditionNode]:
    """Flattens a condition tree into a list of leaf ConditionNodes."""
    leaves: list[ConditionNode] = []
    for cond in tree.conditions:
        if isinstance(cond, ConditionNode):
            leaves.append(cond)
        elif isinstance(cond, ConditionTree):
            leaves.extend(_extract_leaf_conditions(cond))
        elif isinstance(cond, dict):
            if "conditions" in cond:
                leaves.extend(_extract_leaf_conditions(ConditionTree(**cond)))
            elif "field" in cond and "operator" in cond:
                leaves.append(ConditionNode(**cond))
    return leaves


def _find_best_rule_match(
    candidate: RuleIR,
    existing_rules: list[RuleIR],
) -> tuple[Optional[RuleIR], float]:
    """
    Finds the closest matching existing rule for an incoming regulatory obligation.
    Returns (matching_rule, match_score).
    """
    best_rule: Optional[RuleIR] = None
    best_score = 0.0

    cand_category = candidate.category.upper()
    cand_fields = {c.field.lower() for c in _extract_leaf_conditions(candidate.condition_tree)}
    cand_words = set(candidate.rule_name.lower().split() + candidate.description.lower().split())

    for rule in existing_rules:
        score = 0.0
        # Category match
        if rule.category.upper() == cand_category and cand_category != "GENERAL":
            score += 0.40
        elif rule.category.upper() == cand_category:
            score += 0.15

        # Field overlap match
        rule_fields = {c.field.lower() for c in _extract_leaf_conditions(rule.condition_tree)}
        common_fields = cand_fields & rule_fields
        if common_fields:
            score += 0.35

        # Lexical word overlap
        rule_words = set(rule.rule_name.lower().split() + rule.description.lower().split())
        overlap = len(cand_words & rule_words)
        if overlap > 3:
            score += min(0.25, overlap * 0.03)

        if score > best_score:
            best_score = score
            best_rule = rule

    return best_rule, best_score


def run_delta_analysis(
    bank_id: str,
    existing_rules: list[RuleIR],
    circular_obligations: list[dict[str, Any]],
    analysis_name: str = "Regulatory Circular Delta Analysis",
    circular_id: Optional[str] = None,
    circular_number: Optional[str] = None,
) -> DeltaAnalysisResult:
    """
    Compares bank existing rules with circular regulatory obligations and
    generates a classified, explainable delta result.
    """
    analysis_id = str(uuid.uuid4())
    deltas: list[RuleDelta] = []
    matched_existing_rule_ids = set()

    for obl in circular_obligations:
        cand_dict = obl.get("candidate_rule_ir") or {}
        cand_rule = normalize_to_rule_ir(cand_dict)
        clause_id = obl.get("clause_id", "CL-01")
        req_text = obl.get("requirement_text", "")
        citation = {
            "circular_number": circular_number or obl.get("circular_number", "CIRCULAR"),
            "clause_id": clause_id,
            "authority": obl.get("issuing_authority", "RBI"),
            "text": req_text[:300],
        }

        # Attempt to match with existing bank rules
        best_match, score = _find_best_rule_match(cand_rule, existing_rules)

        # Classification logic
        if not best_match or score < 0.35:
            # No existing rule covers this requirement -> ADDITION
            proposed_ir = copy.deepcopy(cand_rule)
            proposed_ir.bank_id = bank_id
            proposed_ir.rule_id = f"PROPOSED-{cand_rule.category[:3]}-{uuid.uuid4().hex[:6].upper()}"

            delta = RuleDelta(
                analysis_id=analysis_id,
                bank_id=bank_id,
                classification="ADDITION",
                category=cand_rule.category,
                rule_name=f"New Mandate: {cand_rule.rule_name}",
                regulatory_obligation_id=obl.get("obligation_id"),
                new_requirement_representation=cand_rule.model_dump(),
                identified_differences=[
                    DiffItem(
                        field="rule_scope",
                        previous_value="[None - Not implemented]",
                        proposed_value=f"New requirement from {clause_id}",
                        diff_type="scope_expanded",
                    )
                ],
                proposed_change=proposed_ir.model_dump(),
                reason=f"New regulatory requirement introduced in clause {clause_id}. Bank currently has no active rule covering this mandate.",
                impact_assessment="Operational compliance gap. Rule must be introduced to avoid regulatory non-compliance penalty.",
                confidence_score=obl.get("confidence", 0.94),
                evidence_sources=[citation],
            )
            deltas.append(delta)

        else:
            matched_existing_rule_ids.add(best_match.rule_id)
            existing_leaves = _extract_leaf_conditions(best_match.condition_tree)
            candidate_leaves = _extract_leaf_conditions(cand_rule.condition_tree)

            diff_items: list[DiffItem] = []
            
            # Compare thresholds
            ex_amt = next((c.value for c in existing_leaves if "amount" in c.field.lower()), None)
            new_amt = next((c.value for c in candidate_leaves if "amount" in c.field.lower()), None)

            ex_days = next((c.value for c in existing_leaves if "day" in c.field.lower() or "retention" in c.field.lower()), None)
            new_days = next((c.value for c in candidate_leaves if "day" in c.field.lower() or "deadline" in c.field.lower()), None)

            # Check for threshold diffs
            if ex_amt is not None and new_amt is not None:
                if ex_amt != new_amt:
                    diff_type = "threshold_lowered" if float(new_amt) < float(ex_amt) else "threshold_raised"
                    diff_items.append(DiffItem(
                        field="transaction_amount",
                        previous_value=ex_amt,
                        proposed_value=new_amt,
                        diff_type=diff_type,
                    ))

            if ex_days is not None and new_days is not None:
                if ex_days != new_days:
                    diff_type = "threshold_lowered" if int(new_days) < int(ex_days) else "threshold_raised"
                    diff_items.append(DiffItem(
                        field="reporting_deadline_days",
                        previous_value=ex_days,
                        proposed_value=new_days,
                        diff_type=diff_type,
                    ))

            # Action difference
            ex_act = best_match.actions[0].action_type if best_match.actions else "FLAG_REVIEW"
            new_act = cand_rule.actions[0].action_type if cand_rule.actions else "FLAG_REVIEW"
            if ex_act != new_act:
                diff_items.append(DiffItem(
                    field="action_type",
                    previous_value=ex_act,
                    proposed_value=new_act,
                    diff_type="action_escalated" if new_act in ("BLOCK", "ESCALATE") else "action_relaxed",
                ))

            # Decide classification based on diffs
            if diff_items:
                classification = "MODIFICATION"
                reason = f"Existing rule '{best_match.rule_name}' requires threshold/action update to align with clause {clause_id}."
                impact = f"Threshold or workflow changes detected ({', '.join(d.field for d in diff_items)}). Transaction monitoring alerts and operational queues will be directly affected."
            elif any(w in req_text.lower() for w in ["clarify", "guidance", "for the avoidance of doubt", "clarification"]):
                classification = "CLARIFICATION"
                reason = f"Clause {clause_id} clarifies the interpretation or reporting guidelines of existing policy."
                impact = "No operational threshold changes required. Informational guidance for compliance auditors."
            elif any(w in req_text.lower() for w in ["subject to approval", "discretionary", "may consider", "complex"]):
                classification = "MANUAL_REVIEW_REQUIRED"
                reason = f"Clause {clause_id} contains conditional or discretionary mandates requiring human compliance officer adjudication."
                impact = "High judgment requirement. Officer must review specific bank exposure before approving."
            else:
                classification = "NO_IMPACT"
                reason = f"Existing rule '{best_match.rule_name}' already fully satisfies or exceeds the criteria stipulated in clause {clause_id}."
                impact = "Zero system changes needed. Current bank controls are already compliant."

            # Construct proposed updated Rule IR
            proposed_ir = copy.deepcopy(best_match)
            if diff_items:
                # Update proposed condition tree with new thresholds
                for d in diff_items:
                    if d.field == "transaction_amount" and new_amt is not None:
                        for cond in _extract_leaf_conditions(proposed_ir.condition_tree):
                            if "amount" in cond.field.lower():
                                cond.value = new_amt
                    elif d.field == "action_type" and new_act is not None:
                        if proposed_ir.actions:
                            proposed_ir.actions[0].action_type = new_act
                proposed_ir.version += 1

            delta = RuleDelta(
                analysis_id=analysis_id,
                bank_id=bank_id,
                classification=classification,
                category=best_match.category,
                rule_name=best_match.rule_name,
                previous_rule_id=best_match.id or best_match.rule_id,
                regulatory_obligation_id=obl.get("obligation_id"),
                previous_rule_representation=best_match.model_dump(),
                new_requirement_representation=cand_rule.model_dump(),
                identified_differences=diff_items,
                proposed_change=proposed_ir.model_dump(),
                reason=reason,
                impact_assessment=impact,
                confidence_score=0.96 if classification in ("MODIFICATION", "NO_IMPACT") else 0.85,
                evidence_sources=[citation],
            )
            deltas.append(delta)

    # Check for REMOVAL (if any existing rules were explicitly superseded or repealed)
    # E.g. circular says "supersedes Rule X" or "repeals guidelines on..."
    full_circ_text = " ".join(obl.get("requirement_text", "") for obl in circular_obligations).lower()
    for rule in existing_rules:
        if rule.rule_id not in matched_existing_rule_ids:
            if any(term in full_circ_text for term in ["repealed", "superseded", "discontinued", "withdrawn"]) and rule.category.lower() in full_circ_text:
                delta = RuleDelta(
                    analysis_id=analysis_id,
                    bank_id=bank_id,
                    classification="REMOVAL",
                    category=rule.category,
                    rule_name=rule.rule_name,
                    previous_rule_id=rule.id or rule.rule_id,
                    previous_rule_representation=rule.model_dump(),
                    identified_differences=[
                        DiffItem(
                            field="is_active",
                            previous_value=True,
                            proposed_value=False,
                            diff_type="threshold_changed",
                        )
                    ],
                    proposed_change={**rule.model_dump(), "is_active": False},
                    reason=f"Rule '{rule.rule_name}' has been marked as repealed or superseded by the new regulatory circular.",
                    impact_assessment="Rule decommissioning required. Automated checks for this rule will be deactivated upon approval.",
                    confidence_score=0.91,
                    evidence_sources=[{"circular_number": circular_number or "CIRCULAR", "text": "Supersession clause detected"}],
                )
                deltas.append(delta)

    # Summary counts
    total = len(deltas)
    additions = sum(1 for d in deltas if d.classification == "ADDITION")
    modifications = sum(1 for d in deltas if d.classification == "MODIFICATION")
    removals = sum(1 for d in deltas if d.classification == "REMOVAL")
    clarifications = sum(1 for d in deltas if d.classification == "CLARIFICATION")
    no_impact = sum(1 for d in deltas if d.classification == "NO_IMPACT")
    manual_review = sum(1 for d in deltas if d.classification == "MANUAL_REVIEW_REQUIRED")

    summary_text = (
        f"Analyzed {total} regulatory obligations against existing bank rules. "
        f"Identified {additions} additions, {modifications} modifications, {removals} removals, "
        f"{clarifications} clarifications, {no_impact} no-impact, and {manual_review} requiring manual review."
    )

    return DeltaAnalysisResult(
        id=analysis_id,
        bank_id=bank_id,
        analysis_name=analysis_name,
        circular_id=circular_id,
        circular_number=circular_number,
        status="COMPLETED",
        total_rules=total,
        additions_count=additions,
        modifications_count=modifications,
        removals_count=removals,
        clarifications_count=clarifications,
        no_impact_count=no_impact,
        manual_review_count=manual_review,
        summary=summary_text,
        deltas=deltas,
    )
