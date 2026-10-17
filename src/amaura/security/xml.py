"""Safe XML parsing utilities protecting against XML injection, bombs, and XXE."""

import xml.etree.ElementTree as ET
from pathlib import Path

from amaura.errors import ExecutionSecurityError

try:
    import defusedxml.ElementTree as DefusedET
    HAS_DEFUSEDXML = True
except ImportError:
    HAS_DEFUSEDXML = False


def safe_parse_xml(xml_path: Path, max_size_bytes: int = 10 * 1024 * 1024) -> ET.Element:
    """Safely parses an untrusted XML file with defense-in-depth protections (C8).
    
    1. Enforces strict file size limits to prevent XML bomb decompression in memory.
    2. Strictly prohibits DTD and entity declarations (rejects Billion Laughs, XXE).
    3. Parses using defusedxml when available, or safely validated ElementTree.
    """
    if not xml_path.is_file():
        raise FileNotFoundError(f"XML file not found: {xml_path}")

    size = xml_path.stat().st_size
    if size > max_size_bytes:
        raise ExecutionSecurityError(
            f"XML file size ({size} bytes) exceeds maximum security limit ({max_size_bytes} bytes)"
        )

    raw_content = xml_path.read_text(encoding="utf-8", errors="replace")
    lowered = raw_content.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ExecutionSecurityError(
            "Untrusted XML entity injection detected: DTD and entity declarations are strictly prohibited."
        )

    if HAS_DEFUSEDXML:
        return DefusedET.fromstring(raw_content)
    return ET.fromstring(raw_content)
