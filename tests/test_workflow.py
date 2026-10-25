from cidan.workflow import graph as workflow_graph
from cidan.workflow.graph import run_graph


def test_workflow_stops_when_ingestion_fails(monkeypatch):
    def fail_ingestion():
        raise RuntimeError("missing API key")

    monkeypatch.setattr(workflow_graph, "ingest", fail_ingestion)
    result = run_graph("blocked-test")
    assert result["stage"] == "failed"
    assert result["error"].startswith("ingestion:")
    assert "impact_reporting" in result["blocked_stages"]
    assert "obligations" not in result
    assert "report" not in result
