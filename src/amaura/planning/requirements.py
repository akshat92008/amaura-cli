"""Task and requirement intake, parsing, and cryptographic integrity validation."""

import re
from pathlib import Path
from typing import Optional

import yaml  # type: ignore[import-untyped]

from amaura.errors import TaskSpecificationError
from amaura.models.task import Requirement, RiskLevel, TaskSpec


def parse_markdown_task(content: str, filename: str = "task.md") -> TaskSpec:
    """Parses a markdown task document into a structured TaskSpec without corrupting inline numbers."""
    lines = content.splitlines()
    instruction_lines: list[str] = []
    requirements: list[Requirement] = []
    constraints: list[str] = []
    assumptions: list[str] = []
    acceptance_criteria: list[str] = []
    current_section = "instruction"

    bullet_regex = re.compile(r"^(?:[-*]|\d+\.)\s+(.+)$")
    strip_bullet_regex = re.compile(r"^(?:[-*]|\d+\.)\s*(?:\[[ xX]\]\s*)?")

    req_index = 1
    for line in lines:
        stripped = line.strip()
        header_match = re.match(r"^#{1,3}\s+(.+)$", stripped)
        if header_match:
            sec_name = header_match.group(1).lower()
            if "requirement" in sec_name:
                current_section = "requirements"
            elif "constraint" in sec_name:
                current_section = "constraints"
            elif "assumption" in sec_name:
                current_section = "assumptions"
            elif "acceptance" in sec_name:
                current_section = "acceptance_criteria"
            else:
                current_section = "instruction"
            continue

        if current_section == "instruction":
            instruction_lines.append(line)

        elif current_section == "requirements":
            if bullet_regex.match(stripped):
                text = strip_bullet_regex.sub("", stripped).strip()
                if text:
                    # Check for mandatory annotation
                    mandatory = not ("[advisory]" in text.lower() or "[optional]" in text.lower())
                    clean_text = re.sub(r"(?i)\[(?:advisory|optional)\]", "", text).strip()

                    # D7: Extract explicit requirement ID if present (e.g. REQ-001: Description)
                    id_match = re.match(r"^((?:REQ[-_][A-Za-z0-9_-]+|[A-Za-z0-9]+[-_]\d+))\s*:\s*(.+)$", clean_text, re.IGNORECASE)
                    if id_match:
                        req_id = id_match.group(1).upper()
                        req_desc = id_match.group(2).strip()
                    else:
                        req_id = f"REQ-{req_index:03d}"
                        req_desc = clean_text

                    # Extract explicit acceptance test criteria if specified (e.g. (acceptance: test_valid_import))
                    acc_match = re.search(r"[\(\[](?:acceptance|test|tests):\s*([^\)\]]+)[\)\]]", req_desc, re.IGNORECASE)
                    acc_criteria: list[str] = []
                    if acc_match:
                        raw_tests = acc_match.group(1)
                        acc_criteria = [t.strip() for t in raw_tests.split(",") if t.strip()]
                        req_desc = (req_desc[:acc_match.start()] + req_desc[acc_match.end():]).strip()

                    req = Requirement(
                        id=req_id,
                        description=req_desc,
                        mandatory=mandatory,
                        risk_level=RiskLevel.HIGH if mandatory else RiskLevel.LOW,
                        acceptance_criteria=acc_criteria,
                    )
                    requirements.append(req)
                    req_index += 1

        elif current_section == "constraints":
            if bullet_regex.match(stripped):
                text = strip_bullet_regex.sub("", stripped).strip()
                if text:
                    constraints.append(text)

        elif current_section == "assumptions":
            if bullet_regex.match(stripped):
                text = strip_bullet_regex.sub("", stripped).strip()
                if text:
                    assumptions.append(text)

        elif current_section == "acceptance_criteria":
            if bullet_regex.match(stripped):
                text = strip_bullet_regex.sub("", stripped).strip()
                if text:
                    acceptance_criteria.append(text)

    instruction = "\n".join(instruction_lines).strip()

    # D7: If no explicit requirements section was found, check ONLY for explicitly tagged REQ-... bullets
    if not requirements:
        for line in lines:
            s = line.strip()
            # Must be an explicitly tagged requirement line, NOT arbitrary bullet point
            m = re.match(r"^(?:[-*]|\d+\.)?\s*(REQ[-_][A-Za-z0-9_-]+)\s*:\s*(.+)$", s, re.IGNORECASE)
            if m:
                req_id = m.group(1).upper()
                clean_desc = m.group(2).strip()
                mandatory = not ("[advisory]" in clean_desc.lower() or "[optional]" in clean_desc.lower())
                clean_desc = re.sub(r"(?i)\[(?:advisory|optional)\]", "", clean_desc).strip()
                acc_match = re.search(r"[\(\[](?:acceptance|test|tests):\s*([^\)\]]+)[\)\]]", clean_desc, re.IGNORECASE)
                acc_criteria = []
                if acc_match:
                    raw_tests = acc_match.group(1)
                    acc_criteria = [t.strip() for t in raw_tests.split(",") if t.strip()]
                    clean_desc = (clean_desc[:acc_match.start()] + clean_desc[acc_match.end():]).strip()

                requirements.append(
                    Requirement(
                        id=req_id,
                        description=clean_desc,
                        mandatory=mandatory,
                        risk_level=RiskLevel.HIGH if mandatory else RiskLevel.LOW,
                        acceptance_criteria=acc_criteria,
                    )
                )

    if not requirements:
        raise TaskSpecificationError(
            "Task specification must contain an explicit '## Requirements' section or explicitly tagged requirements ('REQ-...:'). An empty or untagged requirement set cannot be verified."
        )

    task_id = Path(filename).stem
    task = TaskSpec(
        task_id=task_id,
        instruction=instruction or f"Execute requirements for {task_id}",
        requirements=requirements,
        constraints=constraints,
        assumptions=assumptions,
        acceptance_criteria=acceptance_criteria,
    )
    return task.freeze()


def load_task_file(task_path: Path, expected_hash: Optional[str] = None) -> TaskSpec:
    """Loads and validates a TaskSpec from a Markdown or YAML file, enforcing hash integrity if specified."""
    if not task_path.is_file():
        raise TaskSpecificationError(f"Task file not found: {task_path}")

    content = task_path.read_text(encoding="utf-8")
    suffix = task_path.suffix.lower()

    if suffix in {".yaml", ".yml"}:
        try:
            data = yaml.safe_load(content)
        except Exception as e:
            raise TaskSpecificationError(f"YAML parsing error in task file '{task_path.name}': {e}") from e

        if not isinstance(data, dict):
            raise TaskSpecificationError("YAML task specification must be a dictionary")
        if "task_hash" in data and not isinstance(data["task_hash"], str):
            data["task_hash"] = str(data["task_hash"])
        try:
            task = TaskSpec.model_validate(data)
        except Exception as e:
            raise TaskSpecificationError(f"Task schema validation failed in '{task_path.name}': {e}") from e

        if not task.requirements:
            raise TaskSpecificationError("Task specification must contain at least one requirement.")
        canonical_hash = task.compute_hash()
        # Prevent task hash forgery via YAML frozen and task_hash fields (B6)
        if task.task_hash and task.task_hash != canonical_hash:
            raise TaskSpecificationError(
                f"Task specification tampering detected: Provided task_hash '{task.task_hash}' "
                f"does not match canonical specification hash '{canonical_hash}'."
            )
        task.task_hash = canonical_hash
        task.frozen = True
    else:
        task = parse_markdown_task(content, filename=task_path.name)

    # Mandatory: verify hash integrity against canonical computation (B6)
    if not task.verify_hash():
        raise TaskSpecificationError("Task specification hash verification failed: task is corrupted or modified.")

    # Enforce hash verification if expected_hash provided
    if expected_hash and not task.verify_hash(expected_hash):
        raise TaskSpecificationError(
            f"Task integrity violation: Task specification hash mismatch! "
            f"Expected: {expected_hash}, Computed: {task.task_hash}. The task was modified after freezing."
        )

    return task
