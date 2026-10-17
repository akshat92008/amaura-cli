"""Claim intake and synthesis."""

from pathlib import Path

import yaml  # type: ignore[import-untyped]

from amaura.errors import TaskSpecificationError
from amaura.models.claim import Claim, ClaimOrigin, ClaimStatus, ClaimType
from amaura.models.task import TaskSpec


def derive_claims_from_task(task: TaskSpec) -> list[Claim]:
    """Synthesizes verifiable claims from frozen task requirements."""
    claims: list[Claim] = []
    seen_ids: set[str] = set()
    for req in task.requirements:
        base_id = f"CLM-{req.id}"
        claim_id = base_id
        suffix = 1
        while claim_id in seen_ids:
            claim_id = f"{base_id}_{suffix}"
            suffix += 1
        seen_ids.add(claim_id)

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
    try:
        data = yaml.safe_load(content)
    except Exception as e:
        raise TaskSpecificationError(f"YAML parsing error in claims file '{claims_path.name}': {e}") from e

    if isinstance(data, dict) and "claims" in data:
        items = data["claims"]
    elif isinstance(data, list):
        items = data
    else:
        raise TaskSpecificationError("Claims document must be a list of claims or a dict with a 'claims' key")

    claims: list[Claim] = []
    seen_ids: set[str] = set()
    for idx, item in enumerate(items, start=1):
        if isinstance(item, str):
            c_id = f"CLM-{idx:03d}"
            if c_id in seen_ids:
                raise TaskSpecificationError(f"Duplicate claim ID '{c_id}' detected in claims file.")
            seen_ids.add(c_id)
            claims.append(
                Claim(
                    claim_id=c_id,
                    text=item,
                    claim_type=ClaimType.FACTUAL,
                    origin=ClaimOrigin.AGENT_OUTPUT,
                    importance="high",
                    status=ClaimStatus.NOT_CHECKED,
                )
            )
        elif isinstance(item, dict):
            c_id = item.get("claim_id") or f"CLM-{idx:03d}"
            if c_id in seen_ids:
                raise TaskSpecificationError(f"Duplicate claim ID '{c_id}' detected in claims file: duplicate claim IDs are forbidden.")
            seen_ids.add(c_id)
            item["claim_id"] = c_id
            try:
                claims.append(Claim.model_validate(item))
            except Exception as e:
                raise TaskSpecificationError(f"Claim validation error for '{c_id}': {e}") from e
    return claims
