import logging
from typing import Any

from langgraph.graph import END, StateGraph

from cidan.agents import circular_understanding, policy_mapping, reporting, rule_authoring
from cidan.agents import testing_validation
from cidan.ingestion.retrieval import retrieve
from cidan.ingestion.vector_store import ingest
from cidan.models import Obligation, PolicyFinding
from cidan.workflow.state import WorkflowState

logger = logging.getLogger(__name__)

BLOCKED_AFTER = {
    "ingestion": ["circular_understanding", "policy_mapping", "rule_authoring", "testing_validation", "impact_reporting"],
    "circular_understanding": ["policy_mapping", "rule_authoring", "testing_validation", "impact_reporting"],
    "policy_mapping": ["rule_authoring", "testing_validation", "impact_reporting"],
    "rule_authoring": ["testing_validation", "impact_reporting"],
    "testing_validation": ["impact_reporting"],
    "impact_reporting": [],
}


def build_graph() -> Any:
    def failure(stage: str, exc: Exception) -> dict:
        logger.exception("Workflow stage failed: %s", stage)
        return {
            "stage": "failed",
            "failed_stage": stage,
            "blocked_stages": BLOCKED_AFTER[stage],
            "error": f"{stage}: {exc}",
        }

    def ingest_node(_state: WorkflowState) -> dict:
        try:
            if not _state.get("workflow_id"):
                raise ValueError("A workflow identifier is required.")
            ingest()
            return {
                "documents": retrieve(
                    "loan approval requirements, obligations, scope, thresholds, actions",
                    "circular", k=16,
                ),
                "stage": "ingested",
                "error": None,
            }
        except Exception as exc:
            return failure("ingestion", exc)

    def understand_node(state: WorkflowState) -> dict:
        try:
            results = circular_understanding.run(state["documents"])
            return {"obligations": [item.model_dump(mode="json") for item in results], "stage": "understood"}
        except Exception as exc:
            return failure("circular_understanding", exc)

    def mapping_node(state: WorkflowState) -> dict:
        try:
            obligations = [Obligation.model_validate(item) for item in state["obligations"]]
            from cidan.ingestion.retrieval import retrieve

            findings = []
            for obligation in obligations:
                query = (
                    f"{obligation.text} {obligation.applicability} "
                    f"{obligation.product_type} {obligation.required_action}"
                )
                policy_docs = retrieve(query, "policy_handbook", k=3)
                findings.extend(policy_mapping.run([obligation], policy_docs))
            return {"findings": [item.model_dump(mode="json") for item in findings], "stage": "mapped"}
        except Exception as exc:
            return failure("policy_mapping", exc)

    def author_node(state: WorkflowState) -> dict:
        try:
            findings = [PolicyFinding.model_validate(item) for item in state["findings"]]
            proposals = rule_authoring.run(state["obligations"], findings)
            return {"proposals": [item.model_dump(mode="json") for item in proposals], "stage": "authored"}
        except Exception as exc:
            return failure("rule_authoring", exc)

    def test_node(state: WorkflowState) -> dict:
        try:
            from cidan.models import RuleProposal

            summaries = [
                testing_validation.run(RuleProposal.model_validate(proposal))
                for proposal in state["proposals"]
            ]
            tested = []
            for proposal, summary in zip(state["proposals"], summaries):
                updated = dict(proposal)
                updated["status"] = "validated" if summary.failed == 0 and summary.invalid == 0 else "draft"
                tested.append(updated)
            return {
                "proposals": tested,
                "tests": [item.model_dump(mode="json") for item in summaries],
                "stage": "tested",
            }
        except Exception as exc:
            return failure("testing_validation", exc)

    def report_node(state: WorkflowState) -> dict:
        try:
            from cidan.models import RuleProposal, TestSummary

            report_data = reporting.run(
                [Obligation.model_validate(item) for item in state["obligations"]],
                [PolicyFinding.model_validate(item) for item in state["findings"]],
                [RuleProposal.model_validate(item) for item in state["proposals"]],
                [TestSummary.model_validate(item) for item in state["tests"]],
            )
            return {"report": report_data, "stage": "awaiting_human_review"}
        except Exception as exc:
            return failure("impact_reporting", exc)

    builder = StateGraph(WorkflowState)
    for name, node in [
        ("ingest", ingest_node),
        ("understand", understand_node),
        ("map", mapping_node),
        ("author", author_node),
        ("test", test_node),
        ("report", report_node),
    ]:
        builder.add_node(name, node)
    builder.set_entry_point("ingest")
    chain = [("ingest", "understand"), ("understand", "map"), ("map", "author"),
             ("author", "test"), ("test", "report")]
    for current, following in chain:
        builder.add_conditional_edges(
            current,
            lambda state: "stop" if state.get("error") else "continue",
            {"stop": END, "continue": following},
        )
    builder.add_edge("report", END)
    return builder.compile()


def run_graph(workflow_id: str) -> dict[str, Any]:
    graph = build_graph()
    return graph.invoke({"workflow_id": workflow_id, "stage": "started", "error": None})
