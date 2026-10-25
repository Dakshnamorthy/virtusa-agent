import pytest
from langchain_core.documents import Document

from cidan.agents import circular_understanding, policy_mapping, rule_authoring
from cidan.agents.testing_validation import run as validate_rule_tests
from cidan.models import (
    Citation,
    Obligation,
    PolicyFinding,
    RuleProposal,
    SyntheticTestCase,
)


def make_citation(document_type="circular"):
    return Citation(
        document_id="source-doc",
        filename="CIDAN_Synthetic_Loan_Circular.pdf" if document_type == "circular" else "CIDAN_Synthetic_Policy.pdf",
        document_type=document_type,
        page=1,
        excerpt="For this synthetic demonstration, amounts above Rs 80,000 require a second review.",
        chunk_id="chunk-1" if document_type == "circular" else "policy-chunk",
    )


def make_obligation():
    citation = make_citation()
    return Obligation(
        obligation_id="OBL-1",
        clause_id="CLAUSE-1",
        text="Amounts above Rs 80,000 require a second review.",
        applicability="synthetic demo loans",
        product_type="loan",
        amount_threshold=80_000,
        currency="INR",
        effective_date="not_specified",
        responsible_function="not_specified",
        required_action="second review",
        deadline_or_frequency="not_specified",
        source=citation,
        supporting_excerpt=citation.excerpt,
        confidence=0.9,
    )


def policy_document():
    citation = make_citation("policy_handbook")
    return Document(
        page_content=citation.excerpt,
        metadata={
            "document_id": citation.document_id,
            "filename": citation.filename,
            "document_type": "policy_handbook",
            "page": citation.page,
            "chunk_id": citation.chunk_id,
        },
    )


def test_circular_agent_accepts_only_exact_source_evidence():
    obligation = make_obligation()

    def fake_llm(schema, system, prompt):
        assert "untrusted evidence" in system
        assert "Extract obligations from these circular passages" in prompt
        assert obligation.supporting_excerpt in prompt
        return schema(obligations=[obligation])

    docs = [Document(
        page_content=obligation.supporting_excerpt,
        metadata={
            "document_id": obligation.source.document_id,
            "filename": obligation.source.filename,
            "document_type": "circular",
            "page": obligation.source.page,
            "chunk_id": obligation.source.chunk_id,
        },
    )]
    result = circular_understanding.run(docs, llm_call=fake_llm)
    assert result[0].source_label == "synthetic_demo_source"
    assert result[0].effective_date == "not_specified"


def test_circular_agent_uses_exact_chunk_citation_for_nonverbatim_excerpt():
    obligation = make_obligation().model_copy(
        update={"supporting_excerpt": "This fabricated sentence is not in the PDF."}
    )

    def fake_llm(schema, system, prompt):
        assert "untrusted evidence" in system
        assert "Extract obligations" in prompt
        return schema(obligations=[obligation])

    docs = [Document(
        page_content=make_obligation().supporting_excerpt,
        metadata={
            "document_id": obligation.source.document_id,
            "filename": obligation.source.filename,
            "document_type": "circular",
            "page": obligation.source.page,
            "chunk_id": obligation.source.chunk_id,
        },
    )]
    result = circular_understanding.run(docs, llm_call=fake_llm)
    assert result[0].supporting_excerpt == docs[0].page_content
    assert result[0].source.excerpt == docs[0].page_content[:600]
    assert result[0].confidence <= 0.5
    assert any("not verbatim" in item for item in result[0].ambiguities)


def test_circular_agent_rebuilds_citation_metadata_from_exact_source():
    obligation = make_obligation().model_copy(update={
        "source": make_citation().model_copy(update={
            "excerpt": "invented evidence",
            "page": 5,
            "chunk_id": "actual-chunk",
        })
    })

    def fake_llm(schema, _system, _prompt):
        return schema(obligations=[obligation])

    docs = [Document(
        page_content=obligation.supporting_excerpt,
        metadata={
            "document_id": "source-doc",
            "filename": "CIDAN_Synthetic_Loan_Circular.pdf",
            "document_type": "circular",
            "page": 5,
            "chunk_id": "actual-chunk",
        },
    )]
    result = circular_understanding.run(docs, llm_call=fake_llm)
    assert result[0].source.filename == "CIDAN_Synthetic_Loan_Circular.pdf"
    assert result[0].source.page == 5
    assert result[0].source.chunk_id == "actual-chunk"


def test_circular_agent_withholds_threshold_not_in_cited_source():
    obligation = make_obligation().model_copy(update={"amount_threshold": 180_000})

    def fake_llm(schema, _system, _prompt):
        return schema(obligations=[obligation])

    docs = [Document(
        page_content=obligation.supporting_excerpt,
        metadata={
            "document_id": obligation.source.document_id,
            "filename": obligation.source.filename,
            "document_type": "circular",
            "page": obligation.source.page,
            "chunk_id": obligation.source.chunk_id,
        },
    )]
    result = circular_understanding.run(docs, llm_call=fake_llm)
    assert result[0].amount_threshold is None
    assert result[0].currency is None
    assert result[0].confidence <= 0.4


def test_policy_mapping_agent_uses_cited_passages():
    obligation = make_obligation()
    policy_citation = make_citation("policy_handbook")
    finding = PolicyFinding(
        obligation_id=obligation.obligation_id,
        status="partially_covered",
        matching_policy_provision="Loan decision records",
        circular_citation=obligation.source,
        policy_citations=[policy_citation],
        reasoning="The handbook requires documentation but does not specify a second review.",
        missing_or_inconsistent="Second-review requirement is not explicit.",
        operational_impact="Review routing may not be consistent.",
        recommended_action="Have policy owners assess the wording.",
        confidence=0.8,
    )

    def fake_llm(schema, system, prompt):
        assert "semantic" in system
        assert obligation.text in prompt
        return schema(
            status=finding.status,
            reasoning=finding.reasoning,
            missing_or_inconsistent=finding.missing_or_inconsistent,
            operational_impact=finding.operational_impact,
            recommended_action=finding.recommended_action,
            confidence=finding.confidence,
            evidence_limitations=finding.evidence_limitations,
            cited_policy_chunk_ids=[policy_citation.chunk_id],
        )

    result = policy_mapping.run([obligation], [policy_document()], llm_call=fake_llm)
    assert result[0].status == "partially_covered"


def test_rule_authoring_agent_returns_unapproved_constrained_proposal():
    obligation = make_obligation()
    finding = PolicyFinding(
        obligation_id=obligation.obligation_id,
        status="partially_covered",
        circular_citation=obligation.source,
        reasoning="Retrieved evidence indicates partial coverage.",
        missing_or_inconsistent="Specific review trigger is unclear.",
        operational_impact="Possible inconsistency.",
        recommended_action="Review the draft.",
        confidence=0.7,
    )
    proposal = RuleProposal(
        rule_id="RULE-1",
        version=1,
        business_purpose="Flag synthetic demo loan amounts requiring review.",
        source_obligation_ids=["OBL-1"],
        description="Flag amounts above the demo threshold.",
        trigger_conditions=[{"field": "amount", "operator": "gt", "value": 80_000}],
        required_inputs=["transaction_id", "amount"],
        decision_outcomes=["second review"],
        validation_criteria=["Check values below, at, and above the threshold."],
        rollback_considerations="Restore prior local version.",
        supporting_citations=[obligation.source],
        action="second_review",
        status="validated",
    )

    def fake_llm(schema, system, prompt):
        assert "draft" in system
        assert "OBL-1" in prompt
        return schema(proposals=[proposal])

    result = rule_authoring.run(
        [obligation.model_dump(mode="json")], [finding], llm_call=fake_llm
    )
    assert result[0].status == "draft"


def test_rule_authoring_rejects_citations_from_unlinked_obligations():
    obligation = make_obligation()
    other_obligation = make_obligation().model_copy(update={
        "obligation_id": "OBL-2",
        "source": make_citation().model_copy(update={
            "document_id": "other-source-doc",
            "filename": "other-circular.pdf",
            "chunk_id": "other-chunk",
        }),
    })
    finding = PolicyFinding(
        obligation_id=obligation.obligation_id,
        status="partially_covered",
        circular_citation=obligation.source,
        reasoning="Retrieved evidence indicates partial coverage.",
        missing_or_inconsistent="Specific review trigger is unclear.",
        operational_impact="Possible inconsistency.",
        recommended_action="Review the draft.",
        confidence=0.7,
    )
    proposal = RuleProposal(
        rule_id="RULE-2",
        version=1,
        business_purpose="Flag synthetic demo loan amounts requiring review.",
        source_obligation_ids=["OBL-1"],
        description="Flag amounts above the demo threshold.",
        trigger_conditions=[{"field": "amount", "operator": "gt", "value": 80_000}],
        required_inputs=["transaction_id", "amount"],
        decision_outcomes=["second review"],
        validation_criteria=["Check values below, at, and above the threshold."],
        rollback_considerations="Restore prior local version.",
        supporting_citations=[other_obligation.source],
        action="second_review",
    )

    def fake_llm(schema, _system, _prompt):
        return schema(proposals=[proposal])

    with pytest.raises(ValueError, match="unsupported source citation"):
        rule_authoring.run(
            [
                obligation.model_dump(mode="json"),
                other_obligation.model_dump(mode="json"),
            ],
            [finding],
            llm_call=fake_llm,
        )


def test_testing_agent_executes_llm_proposed_synthetic_cases():
    obligation = make_obligation()
    rule = RuleProposal(
        rule_id="RULE-1",
        version=1,
        business_purpose="Demo threshold boundary.",
        source_obligation_ids=[obligation.obligation_id],
        description="Trigger above the synthetic threshold.",
        trigger_conditions=[{"field": "amount", "operator": "gt", "value": 80_000}],
        required_inputs=["transaction_id", "amount"],
        decision_outcomes=["second review"],
        validation_criteria=["Test the threshold boundary."],
        rollback_considerations="Restore prior local version.",
        supporting_citations=[obligation.source],
        action="second_review",
    )
    cases = [
        SyntheticTestCase(
            test_id=f"boundary-{amount}",
            inputs={"transaction_id": f"tx-{amount}", "amount": amount},
            expected_result=amount > 80_000,
            reason="Verify synthetic threshold boundary.",
            source_obligation_id=obligation.obligation_id,
            category="threshold_boundary",
        )
        for amount in (79_999, 80_000, 80_001)
    ]

    def fake_llm(schema, system, prompt):
        assert "synthetic" in system
        assert rule.rule_id in prompt
        return schema(cases=cases)

    summary = validate_rule_tests(rule, llm_call=fake_llm)
    assert (summary.total, summary.passed, summary.failed, summary.invalid) == (3, 3, 0, 0)
