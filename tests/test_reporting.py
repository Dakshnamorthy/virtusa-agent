from cidan.agents.reporting import run as build_report
from cidan.models import TestResult as RuleTestResult, TestSummary as RuleTestSummary


def test_report_metrics_come_from_executed_test_results():
    summary = RuleTestSummary(
        total=2, passed=1, failed=1, skipped=0, invalid=0, pass_rate=0.5,
        results=[
            RuleTestResult(
                transaction_id="case-1", rule_id="r1", passed=True,
                expected=True, actual=True, message="executed",
            ),
            RuleTestResult(
                transaction_id="case-2", rule_id="r1", passed=False,
                expected=True, actual=False, message="executed",
            ),
        ],
    )

    report = build_report([], [], [], [summary])
    assert report["metrics"]["tests_total"] == 2
    assert report["metrics"]["tests_passed"] == 1
    assert report["metrics"]["tests_failed"] == 1
    assert report["metrics"]["test_pass_rate"] == 0.5
    assert "1 of 2 synthetic tests passed" in report["narrative"]["executive_summary"]
    assert "Not assessed for production deployment" in report["narrative"]["deployment_readiness_assessment"]
