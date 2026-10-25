from pydantic import BaseModel, Field

from cidan.agents.base import invoke_structured
from cidan.models import Citation, PolicyFinding, RuleProposal


class ProposalBatch(BaseModel):
    proposals: list[RuleProposal] = Field(default_factory=list)


SYSTEM = """Draft constrained declarative proposals only for evidence-supported
partially covered or conflicting findings. Use only allowlisted fields/operators.
Never emit executable code, shell, SQL, or arbitrary expressions. Every proposal starts
as draft and cites source evidence. The circular is synthetic, not legally binding.
Do not invent an effective date."""


def run(
    obligations: list[dict],
    findings: list[PolicyFinding],
    llm_call=invoke_structured,
) -> list[RuleProposal]:
    eligible = [
        finding for finding in findings
        if finding.status in {"partially_covered", "potential_conflict"}
    ]
    if not eligible:
        return []
    obligation_by_id = {item["obligation_id"]: item for item in obligations}
    proposals = []
    for finding in eligible:
        item = obligation_by_id[finding.obligation_id]
        compact_obligation = {
            "obligation_id": item["obligation_id"],
            "text": item["text"][:250],
            "amount_threshold": item.get("amount_threshold"),
            "currency": item.get("currency"),
            "effective_date": item.get("effective_date", "not_specified"),
            "required_action": item["required_action"][:160],
            "source": {
                key: item["source"][key]
                for key in ("document_id", "filename", "document_type", "page", "chunk_id")
            }
            | {"excerpt": item["source"]["excerpt"][:160]},
        }
        compact_finding = {
            "obligation_id": finding.obligation_id,
            "status": finding.status,
            "reasoning": finding.reasoning[:220],
            "missing_or_inconsistent": finding.missing_or_inconsistent[:180],
            "operational_impact": finding.operational_impact[:140],
            "recommended_action": finding.recommended_action[:140],
            "confidence": finding.confidence,
            "circular_citation": {
                **finding.circular_citation.model_dump(mode="json"),
                "excerpt": finding.circular_citation.excerpt[:160],
            },
            "policy_citations": [
                {
                    **citation.model_dump(mode="json"),
                    "excerpt": citation.excerpt[:160],
                }
                for citation in finding.policy_citations
            ],
        }
        batch = llm_call(
            ProposalBatch, SYSTEM,
            "Draft at most one proposal for this single eligible finding. Return no "
            "proposal if a safe declarative rule cannot be supported.\n"
            f"Obligation:\n{compact_obligation}\nFinding:\n{compact_finding}",
        )
        if len(batch.proposals) > 1:
            raise ValueError("Rule authoring must return at most one proposal per finding.")
        proposals.extend(batch.proposals)
    eligible_ids = {finding.obligation_id for finding in eligible}
    citations_by_obligation: dict[str, dict[tuple[str, str, str, int, str], str]] = {}
    for finding in eligible:
        source = Citation.model_validate(obligation_by_id[finding.obligation_id]["source"])
        citations = [source, finding.circular_citation, *finding.policy_citations]
        citations_by_obligation[finding.obligation_id] = {
            (
                citation.document_id,
                citation.filename,
                citation.document_type,
                citation.page,
                citation.chunk_id,
            ): citation.excerpt
            for citation in citations
        }
    seen_ids: set[str] = set()
    for proposal in proposals:
        proposal_obligations = set(proposal.source_obligation_ids)
        if not proposal_obligations or not proposal_obligations <= eligible_ids:
            raise ValueError("Proposal references an unsupported policy finding.")
        if len(proposal_obligations) != len(proposal.source_obligation_ids):
            raise ValueError("Proposal contains duplicate source obligation IDs.")
        if proposal.rule_id in seen_ids:
            raise ValueError("The rule authoring agent returned duplicate rule IDs.")
        seen_ids.add(proposal.rule_id)
        supported_citations = {
            key: excerpt
            for obligation_id in proposal.source_obligation_ids
            for key, excerpt in citations_by_obligation[obligation_id].items()
        }
        proposal_citation_keys = set()
        for citation in proposal.supporting_citations:
            citation_key = (
                citation.document_id,
                citation.filename,
                citation.document_type,
                citation.page,
                citation.chunk_id,
            )
            source_excerpt = supported_citations.get(citation_key)
            if not source_excerpt or citation.excerpt not in source_excerpt:
                raise ValueError("Rule proposal contains an unsupported source citation.")
            proposal_citation_keys.add(citation_key)
        for obligation_id in proposal.source_obligation_ids:
            obligation_source = Citation.model_validate(
                obligation_by_id[obligation_id]["source"]
            )
            source_key = (
                obligation_source.document_id,
                obligation_source.filename,
                obligation_source.document_type,
                obligation_source.page,
                obligation_source.chunk_id,
            )
            if source_key not in proposal_citation_keys:
                raise ValueError(
                    "Rule proposal must cite the circular source for each linked obligation."
                )
        proposal.status = "draft"
    return proposals
