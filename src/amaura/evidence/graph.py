"""Evidence graph structure establishing traceable provenance chains."""


from pydantic import BaseModel, Field

from amaura.models.check import CheckDefinition, CheckExecution
from amaura.models.claim import Claim
from amaura.models.evidence import EvidenceItem
from amaura.models.finding import Finding


class ProvenanceChain(BaseModel):
    claim_id: str
    requirement_id: str | None = None
    check_ids: list[str] = Field(default_factory=list)
    execution_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    verdict_status: str = "not_checked"


class EvidenceGraph:
    """Graph linking claims, obligations, checks, executions, evidence items, and findings."""

    def __init__(self):
        self.claims: dict[str, Claim] = {}
        self.checks: dict[str, CheckDefinition] = {}
        self.executions: dict[str, CheckExecution] = {}
        self.evidence: dict[str, EvidenceItem] = {}
        self.findings: dict[str, Finding] = {}

    def add_claim(self, claim: Claim) -> None:
        self.claims[claim.claim_id] = claim

    def add_check(self, check: CheckDefinition) -> None:
        self.checks[check.check_id] = check

    def add_execution(self, execution: CheckExecution) -> None:
        self.executions[execution.execution_id] = execution

    def add_evidence(self, item: EvidenceItem) -> None:
        self.evidence[item.evidence_id] = item

    def add_finding(self, finding: Finding) -> None:
        self.findings[finding.finding_id] = finding

    def get_chain_for_claim(self, claim_id: str) -> ProvenanceChain:
        """Traces the complete 7-step chain for a given claim."""
        claim = self.claims.get(claim_id)
        if not claim:
            return ProvenanceChain(claim_id=claim_id)

        chain = ProvenanceChain(
            claim_id=claim_id,
            requirement_id=claim.target_requirement_id,
            verdict_status=claim.status.value,
        )

        # 1. Identify checks targeting this claim or requirement
        relevant_checks = [
            c for c in self.checks.values()
            if c.target_claim_id == claim_id or (c.target_requirement_id and c.target_requirement_id == claim.target_requirement_id)
        ]
        chain.check_ids = [c.check_id for c in relevant_checks]

        # 2. Identify executions for these checks
        relevant_execs = [e for e in self.executions.values() if e.check_id in chain.check_ids]
        chain.execution_ids = [e.execution_id for e in relevant_execs]

        # 3. Identify evidence for these checks or explicitly tagged with claim_id
        relevant_ev = [
            ev for ev in self.evidence.values()
            if ev.claim_id == claim_id or ev.check_id in chain.check_ids
        ]
        chain.evidence_ids = [ev.evidence_id for ev in relevant_ev]

        # 4. Identify findings
        relevant_findings = [
            f for f in self.findings.values()
            if f.claim_id == claim_id or f.check_id in chain.check_ids
        ]
        chain.finding_ids = [f.finding_id for f in relevant_findings]

        return chain

    def get_unverified_claims(self) -> list[Claim]:
        """Returns all claims that have no associated checks or whose status is not supported."""
        unverified: list[Claim] = []
        for claim in self.claims.values():
            chain = self.get_chain_for_claim(claim.claim_id)
            if not chain.check_ids or claim.status.value != "supported":
                unverified.append(claim)
        return unverified

    def to_dict(self) -> dict:
        """Serializes the complete evidence graph into a dictionary for persistence."""
        return {
            "claims": {k: v.model_dump(mode="json") for k, v in self.claims.items()},
            "checks": {k: v.model_dump(mode="json") for k, v in self.checks.items()},
            "executions": {k: v.model_dump(mode="json") for k, v in self.executions.items()},
            "evidence": {k: v.model_dump(mode="json") for k, v in self.evidence.items()},
            "findings": {k: v.model_dump(mode="json") for k, v in self.findings.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceGraph":
        """Reconstructs an EvidenceGraph from a serialized dictionary."""
        graph = cls()
        for c in data.get("claims", {}).values():
            graph.add_claim(Claim.model_validate(c))
        for chk in data.get("checks", {}).values():
            graph.add_check(CheckDefinition.model_validate(chk))
        for ex in data.get("executions", {}).values():
            graph.add_execution(CheckExecution.model_validate(ex))
        for ev in data.get("evidence", {}).values():
            graph.add_evidence(EvidenceItem.model_validate(ev))
        for f in data.get("findings", {}).values():
            graph.add_finding(Finding.model_validate(f))
        return graph
