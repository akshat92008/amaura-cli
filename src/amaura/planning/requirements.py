"""Task and requirement intake, parsing, and cryptographic integrity validation."""

import re
from pathlib import Path
from typing import Optional

import yaml

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
                    req = Requirement(
                        id=f"REQ-{req_index:03d}",
                        description=text,
                        mandatory=mandatory,
                        risk_level=RiskLevel.HIGH if mandatory else RiskLevel.LOW,
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

    # If no explicit requirements section was found, parse top-level bullets as requirements
    if not requirements:
        for line in lines:
            s = line.strip()
            if bullet_regex.match(s):
                clean_text = strip_bullet_regex.sub("", s).strip()
                if len(clean_text) > 5:
                    requirements.append(
                        Requirement(
                            id=f"REQ-{len(requirements)+1:03d}",
                            description=clean_text,
                            mandatory=True,
                            risk_level=RiskLevel.MEDIUM,
                        )
                    )

    if not requirements:
        raise TaskSpecificationError(
            "Task specification must contain at least one verifiable requirement. An empty requirement set cannot be verified."
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
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise TaskSpecificationError("YAML task specification must be a dictionary")
        task = TaskSpec.model_validate(data)
        if not task.requirements:
            raise TaskSpecificationError("Task specification must contain at least one requirement.")
        if not task.frozen:
            task.freeze()
    else:
        task = parse_markdown_task(content, filename=task_path.name)

    # Enforce hash verification if expected_hash provided
    if expected_hash and task.task_hash != expected_hash:
        raise TaskSpecificationError(
            f"Task integrity violation: Task specification hash mismatch! "
            f"Expected: {expected_hash}, Computed: {task.task_hash}. The task was modified after freezing."
        )

    return task
