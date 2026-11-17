"""
CIDAN Rule Testing & Simulation Engine
Milestone 3 - Isolated Testing Environment, Boundary Evaluation, Regression & Deployment Safety Blocker
"""
from __future__ import annotations

import copy
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple
import uuid

from pydantic import BaseModel, ConfigDict, Field

TestCaseType = Literal["POSITIVE", "NEGATIVE", "BOUNDARY", "REGRESSION", "CONFLICT", "DEPENDENCY"]
TestRunStatus = Literal["PENDING", "RUNNING", "PASSED", "FAILED", "PARTIALLY_PASSED", "CANCELLED"]


class RuleTestCase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    suite_id: str
    bank_id: str
    rule_id: str
    test_type: TestCaseType
    scenario_name: str
    input_data: dict[str, Any]
    expected_result: dict[str, Any]  # e.g. {"triggered": True, "action": "FLAG_REVIEW"}
    is_ai_generated: bool = False
    is_mandatory: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RuleTestSuite(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bank_id: str
    rule_id: str
    rule_version: str
    suite_name: str
    description: str = ""
    test_cases: list[RuleTestCase] = Field(default_factory=list)
    created_by: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TestCaseResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str
    test_case_id: str
    test_type: TestCaseType
    scenario_name: str
    status: Literal["PASS", "FAIL", "ERROR"]
    actual_output: dict[str, Any]
    expected_output: dict[str, Any]
    execution_duration_ms: int = 0
    error_message: Optional[str] = None


class RuleTestRun(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    suite_id: str
    bank_id: str
    rule_id: str
    rule_version: str
    total_test_cases: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    pass_percentage: float = 0.0
    execution_duration_ms: int = 0
    status: TestRunStatus = "PENDING"
    started_by: str
    results: list[TestCaseResult] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _evaluate_condition(op: str, actual_val: Any, target_val: Any) -> bool:
    """Evaluates an individual ConditionNode operator against actual input value."""
    if actual_val is None:
        return False
    try:
        # Numeric comparison
        if isinstance(target_val, (int, float)) or (isinstance(target_val, str) and target_val.replace(".", "", 1).isdigit()):
            num_actual = float(actual_val)
            num_target = float(target_val)
            if op in ("gte", ">="):
                return num_actual >= num_target
            if op in ("lte", "<="):
                return num_actual <= num_target
            if op in ("gt", ">"):
                return num_actual > num_target
            if op in ("lt", "<"):
                return num_actual < num_target
            if op in ("eq", "=="):
                return num_actual == num_target
            if op in ("neq", "!="):
                return num_actual != num_target

        # Boolean comparison
        if isinstance(target_val, bool) or str(target_val).lower() in ("true", "false"):
            bool_actual = bool(actual_val) if not isinstance(actual_val, str) else actual_val.lower() == "true"
            bool_target = bool(target_val) if not isinstance(target_val, str) else target_val.lower() == "true"
            if op in ("eq", "=="):
                return bool_actual == bool_target
            if op in ("neq", "!="):
                return bool_actual != bool_target

        # String comparison
        str_actual = str(actual_val).strip().lower()
        str_target = str(target_val).strip().lower()
        if op in ("eq", "=="):
            return str_actual == str_target
        if op in ("contains", "in"):
            return str_target in str_actual
    except Exception:
        return False
    return False


def _evaluate_rule_ir(rule_ir: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """
    Executes a Rule IR condition tree in isolated simulation against input payload.
    Returns: {"triggered": bool, "actions": list, "matched_conditions": list}
    """
    tree = rule_ir.get("condition_tree", {})
    operator = tree.get("operator", "AND").upper()
    conditions = tree.get("conditions", [])

    results: list[bool] = []
    matched_conditions = []

    for c in conditions:
        field = c.get("field")
        op = c.get("operator", "eq")
        target_val = c.get("value")
        actual_val = payload.get(field)

        eval_res = _evaluate_condition(op, actual_val, target_val)
        results.append(eval_res)
        if eval_res:
            matched_conditions.append(field)

    if operator == "AND":
        triggered = all(results) if results else False
    elif operator == "OR":
        triggered = any(results) if results else False
    else:
        triggered = all(results) if results else False

    actions = rule_ir.get("actions", []) if triggered else []
    return {
        "triggered": triggered,
        "actions": actions,
        "matched_conditions": matched_conditions,
    }


class RuleTestingService:
    """Simulation engine for isolated rule verification and test generation."""

    @staticmethod
    def generate_boundary_and_functional_cases(
        suite_id: str,
        bank_id: str,
        rule_ir: dict[str, Any],
    ) -> list[RuleTestCase]:
        """
        Automatically derives Positive, Negative, and Boundary test cases
        from the rule's ConditionTree to ensure robust verification.
        """
        cases: list[RuleTestCase] = []
        rule_id = rule_ir.get("rule_id", "RULE-SIM")
        tree = rule_ir.get("condition_tree", {})
        conditions = tree.get("conditions", [])

        # Positive Baseline Input
        positive_input: dict[str, Any] = {}
        negative_input: dict[str, Any] = {}

        for c in conditions:
            field = c.get("field")
            val = c.get("value")
            op = c.get("operator", "gte")

            if isinstance(val, bool):
                positive_input[field] = val
                negative_input[field] = not val

            elif isinstance(val, (int, float)):
                # Baseline values
                positive_input[field] = val + 1000.0 if op in ("gte", "gt") else val - 10.0
                negative_input[field] = max(0.0, val - 5000.0) if op in ("gte", "gt") else val + 5000.0

                # Generate Boundary Cases around the threshold
                # Example: for 500,000 threshold -> 499,999, 500,000, 500,001
                cases.append(
                    RuleTestCase(
                        suite_id=suite_id,
                        bank_id=bank_id,
                        rule_id=rule_id,
                        test_type="BOUNDARY",
                        scenario_name=f"Boundary Test: Exactly At Threshold ({field} = {val})",
                        input_data={field: val},
                        expected_result={"triggered": op in ("gte", "lte", "eq")},
                        is_ai_generated=True,
                    )
                )
                cases.append(
                    RuleTestCase(
                        suite_id=suite_id,
                        bank_id=bank_id,
                        rule_id=rule_id,
                        test_type="BOUNDARY",
                        scenario_name=f"Boundary Test: Just Below Threshold ({field} = {val - 1})",
                        input_data={field: max(0.0, val - 1.0)},
                        expected_result={"triggered": op in ("lte", "lt")},
                        is_ai_generated=True,
                    )
                )
                cases.append(
                    RuleTestCase(
                        suite_id=suite_id,
                        bank_id=bank_id,
                        rule_id=rule_id,
                        test_type="BOUNDARY",
                        scenario_name=f"Boundary Test: Just Above Threshold ({field} = {val + 1})",
                        input_data={field: val + 1.0},
                        expected_result={"triggered": op in ("gte", "gt")},
                        is_ai_generated=True,
                    )
                )

            else:
                positive_input[field] = str(val)
                negative_input[field] = "NON_MATCHING_VALUE"

        # Functional Positive Case
        cases.append(
            RuleTestCase(
                suite_id=suite_id,
                bank_id=bank_id,
                rule_id=rule_id,
                test_type="POSITIVE",
                scenario_name=f"Positive Verification: Valid Trigger Criteria for {rule_id}",
                input_data=positive_input,
                expected_result={"triggered": True},
                is_ai_generated=True,
            )
        )

        # Functional Negative Case
        cases.append(
            RuleTestCase(
                suite_id=suite_id,
                bank_id=bank_id,
                rule_id=rule_id,
                test_type="NEGATIVE",
                scenario_name=f"Negative Verification: Below/Outside Trigger Criteria for {rule_id}",
                input_data=negative_input,
                expected_result={"triggered": False},
                is_ai_generated=True,
            )
        )

        # Regression Case
        cases.append(
            RuleTestCase(
                suite_id=suite_id,
                bank_id=bank_id,
                rule_id=rule_id,
                test_type="REGRESSION",
                scenario_name=f"Regression Guard: Standard Legacy Transaction Profile for {rule_id}",
                input_data={**positive_input, "transaction_currency": "INR", "is_domestic": True},
                expected_result={"triggered": True},
                is_ai_generated=True,
            )
        )

        return cases

    @staticmethod
    def execute_test_suite(
        suite: RuleTestSuite,
        rule_ir_snapshot: dict[str, Any],
        started_by: str,
    ) -> RuleTestRun:
        """
        Executes all test cases within the suite in an isolated sandbox.
        Records exact execution durations and pass/fail states.
        """
        t0 = time.time()
        run_id = str(uuid.uuid4())
        results: list[TestCaseResult] = []

        passed_count = 0
        failed_count = 0

        for tc in suite.test_cases:
            tc_start = time.time()
            sim_output = _evaluate_rule_ir(rule_ir_snapshot, tc.input_data)
            duration_ms = int((time.time() - tc_start) * 1000)

            # Evaluate expected vs actual
            expected_triggered = tc.expected_result.get("triggered")
            actual_triggered = sim_output.get("triggered")

            is_pass = (expected_triggered == actual_triggered)
            status: Literal["PASS", "FAIL", "ERROR"] = "PASS" if is_pass else "FAIL"

            if is_pass:
                passed_count += 1
            else:
                failed_count += 1

            err_msg = None
            if not is_pass:
                err_msg = (
                    f"Assertion failed: expected triggered={expected_triggered}, "
                    f"but rule simulation produced triggered={actual_triggered}."
                )

            results.append(
                TestCaseResult(
                    run_id=run_id,
                    test_case_id=tc.id,
                    test_type=tc.test_type,
                    scenario_name=tc.scenario_name,
                    status=status,
                    actual_output=sim_output,
                    expected_output=tc.expected_result,
                    execution_duration_ms=duration_ms,
                    error_message=err_msg,
                )
            )

        total_cases = len(suite.test_cases)
        total_duration_ms = int((time.time() - t0) * 1000)
        pass_pct = (passed_count / total_cases * 100.0) if total_cases > 0 else 0.0

        if passed_count == total_cases and total_cases > 0:
            final_status: TestRunStatus = "PASSED"
        elif passed_count > 0:
            final_status = "PARTIALLY_PASSED"
        else:
            final_status = "FAILED"

        return RuleTestRun(
            id=run_id,
            suite_id=suite.id,
            bank_id=suite.bank_id,
            rule_id=suite.rule_id,
            rule_version=suite.rule_version,
            total_test_cases=total_cases,
            passed_tests=passed_count,
            failed_tests=failed_count,
            pass_percentage=round(pass_pct, 2),
            execution_duration_ms=total_duration_ms,
            status=final_status,
            started_by=started_by,
            results=results,
        )
