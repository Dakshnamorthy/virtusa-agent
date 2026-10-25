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

    class Narrative:
        def model_dump(self, mode):
            assert mode == "json"
            return {
                "executive_summary": "Review required.",
                "operational_impact": "Local only.",
                "recommended_human_review_actions": [],
                "evidence_limitations": [],
                "deployment_readiness_assessment": "Not deployment-ready.",
            }

    def fake_llm(_schema, _system_prompt, user_prompt):
        assert _schema.__name__ == "ReportNarrative"
        assert "Summarize only structured results" in _system_prompt
        assert "'tests_total': 2" in user_prompt
        assert "'tests_passed': 1" in user_prompt
        return Narrative()

    report = build_report([], [], [], [summary], llm_call=fake_llm)
    assert report["metrics"]["tests_total"] == 2
    assert report["metrics"]["tests_passed"] == 1
    assert report["metrics"]["tests_failed"] == 1
    assert report["metrics"]["test_pass_rate"] == 0.5
