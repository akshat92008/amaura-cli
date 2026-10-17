"""Task and requirement intake and compilation."""

import re
from pathlib import Path

import yaml

from amaura.errors import TaskSpecificationError
from amaura.models.task import Requirement, RiskLevel, TaskSpec


def parse_markdown_task(content: str, filename: str = "task.md") -> TaskSpec:
    """Parses a markdown task document into a structured TaskSpec."""
    lines = content.splitlines()
    instruction_lines = []
    requirements: list[Requirement] = []
    constraints: list[str] = []
    assumptions: list[str] = []
    current_section = "instruction"

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
            item_match = re.match(r"^[-*]|\d+\.\s*(.+)$", stripped)
            if item_match and stripped:
                text = re.sub(r"^[-*]|\d+\.\s*(\[[ xX]\]\s*)?", "", stripped).strip()
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
            if stripped.startswith(("-", "*")) or re.match(r"^\d+\.", stripped):
                text = re.sub(r"^[-*]|\d+\.\s*", "", stripped).strip()
                if text:
                    constraints.append(text)
        elif current_section == "assumptions":
            if stripped.startswith(("-", "*")) or re.match(r"^\d+\.", stripped):
                text = re.sub(r"^[-*]|\d+\.\s*", "", stripped).strip()
                if text:
                    assumptions.append(text)

    instruction = "\n".join(instruction_lines).strip()
    if not instruction and not requirements:
        raise TaskSpecificationError("Task document contains neither instructions nor requirements")

    # If no explicit requirements section was found, extract bullet points or paragraphs as requirements
    if not requirements:
        for idx, line in enumerate(lines, start=1):
            s = line.strip()
            if s.startswith(("-", "*", "1.", "2.", "3.", "4.", "5.")):
                clean_text = re.sub(r"^[-*]|\d+\.\s*", "", s).strip()
                if len(clean_text) > 5:
                    requirements.append(
                        Requirement(
                            id=f"REQ-{len(requirements)+1:03d}",
                            description=clean_text,
                            mandatory=True,
                            risk_level=RiskLevel.MEDIUM,
                        )
                    )

    task_id = Path(filename).stem
    task = TaskSpec(
        task_id=task_id,
        instruction=instruction or f"Execute requirements for {task_id}",
        requirements=requirements,
        constraints=constraints,
        assumptions=assumptions,
    )
    return task.freeze()


def load_task_file(task_path: Path) -> TaskSpec:
    """Loads a TaskSpec from a Markdown, YAML, or JSON file."""
    if not task_path.is_file():
        raise TaskSpecificationError(f"Task file not found: {task_path}")

    content = task_path.read_text(encoding="utf-8")
    suffix = task_path.suffix.lower()

    if suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise TaskSpecificationError("YAML task specification must be a dictionary")
        task = TaskSpec.model_validate(data)
        return task.freeze()
    else:
        return parse_markdown_task(content, filename=task_path.name)
