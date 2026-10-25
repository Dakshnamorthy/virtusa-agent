import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cidan.models import Obligation, PolicyFinding, RuleProposal, TestSummary


def _build_narrative(
    obligations: list[Obligation],
    findings: list[PolicyFinding],
    proposals: list[RuleProposal],
    metrics: dict[str, Any],
) -> dict[str, Any]:
    review_findings = [
        item for item in findings
        if item.status in {"partially_covered", "not_found", "potential_conflict", "requires_human_review"}
    ]
    actions = list(dict.fromkeys(
        item.recommended_action.strip()
        for item in review_findings
        if item.recommended_action.strip()
    ))
    limitations = list(dict.fromkeys(
        [
            limitation.strip()
            for item in findings
            for limitation in item.evidence_limitations
            if limitation.strip()
        ] + [
            ambiguity.strip()
            for item in obligations
            for ambiguity in item.ambiguities
            if ambiguity.strip()
        ]
    ))
    return {
        "executive_summary": (
            f"Extracted {metrics['obligations_extracted']} obligations and generated "
            f"{metrics['policy_findings']} policy findings. "
            f"{metrics['draft_rules_generated']} draft rules were generated; "
            f"{metrics['tests_passed']} of {metrics['tests_total']} synthetic tests passed."
        ),
        "operational_impact": (
            f"{len(review_findings)} policy findings require or recommend human review. "
            "This report does not determine legal compliance or production readiness."
        ),
        "recommended_human_review_actions": actions[:5],
        "evidence_limitations": limitations[:10],
        "deployment_readiness_assessment": (
            "Not assessed for production deployment; human review is required."
        ),
    }


def run(
    obligations: list[Obligation],
    findings: list[PolicyFinding],
    proposals: list[RuleProposal],
    tests: list[TestSummary],
) -> dict:
    status_counts: dict[str, int] = {}
    for finding in findings:
        status_counts[finding.status] = status_counts.get(finding.status, 0) + 1
    metrics: dict[str, Any] = {
        "obligations_extracted": len(obligations),
        "policy_findings": len(findings),
        "policy_mapping_status_counts": status_counts,
        "draft_rules_generated": len(proposals),
        "tests_total": sum(item.total for item in tests),
        "tests_passed": sum(item.passed for item in tests),
        "tests_failed": sum(item.failed for item in tests),
        "tests_skipped": sum(item.skipped for item in tests),
        "tests_invalid": sum(item.invalid for item in tests),
    }
    total = int(metrics["tests_total"])
    metrics["test_pass_rate"] = int(metrics["tests_passed"]) / total if total else None
    return {
        "report_id": "CIDAN-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_status": "synthetic_demo_source",
        "disclaimer": "Synthetic demo only; not an official RBI circular or legal advice.",
        "narrative": _build_narrative(obligations, findings, proposals, metrics),
        "metrics": metrics,
        "obligations": [item.model_dump(mode="json") for item in obligations],
        "policy_findings": [item.model_dump(mode="json") for item in findings],
        "proposed_rules": [item.model_dump(mode="json") for item in proposals],
        "tests": [item.model_dump(mode="json") for item in tests],
        "approval_required": True,
    }


def render_markdown(report: dict) -> str:
    narrative = report["narrative"]
    metrics = report["metrics"]
    lines = [
        "# CIDAN Impact Report",
        "",
        f"> {report['disclaimer']}",
        "",
        f"- Report ID: {report['report_id']}",
        f"- Source status: {report['source_status']}",
        f"- Generated at: {report['generated_at_utc']}",
        "",
        "## Executive summary",
        narrative["executive_summary"],
        "",
        "## Obligations",
    ]
    for obligation in report["obligations"]:
        source = obligation["source"]
        lines.extend([
            f"- **{obligation['obligation_id']}**: {obligation['text']}",
            f"  - Citation: {source['filename']} page {source['page']} "
            f"(chunk `{source['chunk_id']}`): “{source['excerpt']}”",
            f"  - Effective date: {obligation['effective_date']}",
            f"  - Confidence: {obligation['confidence']}",
        ])
    lines.extend(["", "## Policy mapping"])
    for finding in report["policy_findings"]:
        lines.extend([
            f"- **{finding['obligation_id']} — {finding['status']}**: {finding['reasoning']}",
            f"  - Operational impact: {finding['operational_impact']}",
            f"  - Recommended action: {finding['recommended_action']}",
            f"  - Evidence limitations: {', '.join(finding['evidence_limitations']) or 'None listed'}",
        ])
        for citation in [finding["circular_citation"], *finding["policy_citations"]]:
            lines.append(
                f"  - Citation: {citation['filename']} page {citation['page']} "
                f"(chunk `{citation['chunk_id']}`): “{citation['excerpt']}”"
            )
    lines.extend(["", "## Proposed rule changes"])
    if not report["proposed_rules"]:
        lines.append("No rule proposals were generated.")
    for rule in report["proposed_rules"]:
        lines.extend([
            f"- **{rule['rule_id']} v{rule['version']} — {rule['status']}**: {rule['description']}",
            f"  - Business purpose: {rule['business_purpose']}",
            f"  - Conditions: `{rule['trigger_conditions']}`",
            f"  - Required inputs: {', '.join(rule['required_inputs'])}",
            f"  - Risk: {rule['risk_level']}; effective date: {rule['effective_date']}",
            f"  - Exceptions: {', '.join(rule['exceptions']) or 'None specified'}",
            f"  - Unresolved questions: {', '.join(rule['unresolved_questions']) or 'None listed'}",
            f"  - Rollback: {rule['rollback_considerations']}",
        ])
        for citation in rule["supporting_citations"]:
            lines.append(
                f"  - Citation: {citation['filename']} page {citation['page']} "
                f"(chunk `{citation['chunk_id']}`): “{citation['excerpt']}”"
            )
    lines.extend([
        "",
        "## Validation results",
        f"- Total: {metrics['tests_total']}",
        f"- Passed: {metrics['tests_passed']}",
        f"- Failed: {metrics['tests_failed']}",
        f"- Invalid: {metrics['tests_invalid']}",
        f"- Skipped: {metrics['tests_skipped']}",
        f"- Pass rate: {metrics['test_pass_rate']}",
    ])
    for group in report["tests"]:
        for test in group["results"]:
            lines.append(
                f"- `{test['transaction_id']}` ({test['rule_id']}): "
                f"{'PASS' if test['passed'] else 'FAIL'} — {test['message']}"
            )
    lines.extend([
        "",
        "## Operational impact",
        narrative["operational_impact"],
        "",
        "## Human review actions",
        *[f"- {item}" for item in narrative["recommended_human_review_actions"]],
        "",
        "## Evidence limitations",
        *[f"- {item}" for item in narrative["evidence_limitations"]],
        "",
        "## Deployment readiness",
        narrative["deployment_readiness_assessment"],
        "",
        "Rule approval is a local workflow status only. No production system was modified.",
        "",
    ])
    return "\n".join(lines)


def save(report: dict, output_dir: str | Path) -> tuple[Path, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "validation_report.json"
    markdown_path = output / "validation_report.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path
