import pytest
from pydantic import ValidationError

from cidan.agents.policy_mapping import run as map_policies
from cidan.models import Citation, Obligation


def sample_obligation():
    citation = Citation(
        document_id="doc", filename="circular.pdf", document_type="circular",
        page=1, excerpt="Loan decisions must be recorded.", chunk_id="chunk",
    )
    return Obligation(
        obligation_id="OBL-1", clause_id="section-1",
        text="Record the decision.", applicability="personal loans",
        product_type="loan", responsible_function="not_specified",
        required_action="record the decision", source=citation,
        supporting_excerpt="Loan decisions must be recorded.", confidence=0.8,
    )


def test_missing_effective_date_is_not_guessed():
    obligation = sample_obligation()
    assert obligation.effective_date == "not_specified"
    assert obligation.source_label == "synthetic_demo_source"


def test_unsupported_effective_date_type_is_rejected():
    data = sample_obligation().model_dump()
    data["effective_date"] = 20250101
    with pytest.raises(ValidationError):
        Obligation.model_validate(data)


def test_policy_mapping_without_retrieved_evidence_is_inconclusive():
    findings = map_policies([sample_obligation()], [])
    assert len(findings) == 1
    assert findings[0].status == "requires_human_review"
    assert findings[0].confidence == 0
    assert not findings[0].policy_citations
