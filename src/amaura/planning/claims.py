"""Claim intake and synthesis."""

from pathlib import Path

import yaml

from amaura.errors import TaskSpecificationError
from amaura.models.claim import Claim, ClaimOrigin, ClaimStatus, ClaimType
from amaura.models.task import TaskSpec


def derive_claims_from_task(task: TaskSpec) -> list[Claim]:
    """Synthesizes verifiable claims from frozen task requirements."""
    claims: list[Claim] = []
    for req in task.requirements:
        claim_id = f"CLM-{req.id}"
        claims.append(
            Claim(
                claim_id=claim_id,
                text=f"The implementation satisfies requirement {req.id}: {req.description}",
                claim_type=ClaimType.BEHAVIORAL,
                origin=ClaimOrigin.USER_REQUIREMENT,
                importance="critical" if req.mandatory else "medium",
                required_evidence=f"Demonstrated passing test or deterministic check validating: {req.description}",
                target_requirement_id=req.id,
                status=ClaimStatus.NOT_CHECKED,
            )
        )
    return claims


def load_claims_file(claims_path: Path) -> list[Claim]:
    """Loads explicit claims from a YAML or JSON file."""
    if not claims_path.is_file():
        raise TaskSpecificationError(f"Claims file not found: {claims_path}")

    content = claims_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    if isinstance(data, dict) and "claims" in data:
        items = data["claims"]
    elif isinstance(data, list):
        items = data
    else:
        raise TaskSpecificationError("Claims document must be a list of claims or a dict with a 'claims' key")

    claims: list[Claim] = []
    for idx, item in enumerate(items, start=1):
        if isinstance(item, str):
            claims.append(
                Claim(
                    claim_id=f"CLM-{idx:03d}",
                    text=item,
                    claim_type=ClaimType.FACTUAL,
                    origin=ClaimOrigin.AGENT_OUTPUT,
                    importance="high",
                    status=ClaimStatus.NOT_CHECKED,
                )
            )
        elif isinstance(item, dict):
            if "claim_id" not in item:
                item["claim_id"] = f"CLM-{idx:03d}"
            claims.append(Claim.model_validate(item))
    return claims
