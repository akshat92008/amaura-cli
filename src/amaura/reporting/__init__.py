"""Reporting formats for verification runs."""

from amaura.reporting.json_report import generate_json_report
from amaura.reporting.markdown import generate_markdown_report

__all__ = ["generate_json_report", "generate_markdown_report"]
