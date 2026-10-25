from pydantic import BaseModel, Field

from cidan.agents.base import invoke_structured
from cidan.models import RuleProposal, SyntheticTestCase, TestResult, TestSummary
from cidan.rule_engine import evaluate


class TestCaseBatch(BaseModel):
    cases: list[SyntheticTestCase] = Field(min_length=1)


SYSTEM = """Generate synthetic test cases for the supplied declarative rule, including
positive, negative, boundary, missing/invalid input, exception and regression cases
where relevant. Expected results must follow the source-supported rule. Never include
real customer data or represent tests as actual regulatory requirements."""


def run(rule: RuleProposal, llm_call=invoke_structured) -> TestSummary:
    batch = llm_call(
        TestCaseBatch, SYSTEM,
        f"Rule proposal:\n{rule.model_dump(mode='json')}\n"
        "Generate meaningful synthetic scenarios and explain each expected result.",
    )
    results: list[TestResult] = []
    invalid = 0
    for case in batch.cases:
        if case.source_obligation_id not in rule.source_obligation_ids:
            invalid += 1
            results.append(TestResult(
                transaction_id=case.test_id, rule_id=rule.rule_id, passed=False,
                expected=case.expected_result, actual=None,
                message="Invalid test input: source obligation is not part of this rule.",
            ))
            continue
        try:
            actual = evaluate(rule.model_dump(mode="json"), case.inputs)["triggered"]
            passed = actual == case.expected_result
            results.append(TestResult(
                transaction_id=case.test_id, rule_id=rule.rule_id, passed=passed,
                expected=case.expected_result, actual=actual,
                message="Executed synthetic test" if passed else "Expected and actual differ",
            ))
        except (ValueError, TypeError, KeyError) as exc:
            invalid += 1
            results.append(TestResult(
                transaction_id=case.test_id, rule_id=rule.rule_id, passed=False,
                expected=case.expected_result, actual=None, message=f"Invalid test input: {exc}",
            ))
    total = len(results)
    passed = sum(result.passed for result in results)
    failed = sum(not result.passed for result in results) - invalid
    return TestSummary(
        total=total, passed=passed, failed=max(failed, 0), skipped=0, invalid=invalid,
        pass_rate=passed / total if total else None, results=results,
    )
