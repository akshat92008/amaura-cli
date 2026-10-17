"""Markdown report generator matching Amaura specification."""


from amaura.models.check import CheckStatus
from amaura.models.claim import ClaimStatus
from amaura.models.run import RunRecord


def generate_markdown_report(record: RunRecord) -> str:
    """Generates an evidence-backed, human-readable verification report."""
    md: list[str] = []

    md.append("# Amaura Audit Report")
    md.append("")
    md.append(f"**Run ID:** `{record.run_id}`  ")
    md.append(f"**Timestamp:** `{record.timestamp}`  ")
    md.append(f"**Policy:** `{record.policy_applied}`  ")
    if record.git_commit:
        md.append(f"**Git Commit:** `{record.git_commit[:8]}` (clean: `{record.git_clean}`)  ")
    md.append("")

    # Task section
    md.append(f"### Task: {record.task.instruction.splitlines()[0] if record.task.instruction else record.task.task_id}")
    if record.task.task_hash:
        md.append(f"*Task Hash:* `{record.task.task_hash[:12]}...` (Frozen: {record.task.frozen})")
    md.append("")

    # Checks categorization
    exec_map = {e.check_id: e for e in record.executions}
    passed_checks = [c for c in record.checks if exec_map.get(c.check_id) and exec_map[c.check_id].status == CheckStatus.PASSED]
    failed_checks = [c for c in record.checks if exec_map.get(c.check_id) and exec_map[c.check_id].status in (CheckStatus.FAILED, CheckStatus.ERROR, CheckStatus.TIMED_OUT)]
    unrun_checks = [c for c in record.checks if not exec_map.get(c.check_id) or exec_map[c.check_id].status == CheckStatus.NOT_RUN]

    md.append("### Supported Checks")
    if passed_checks:
        for c in passed_checks:
            e = exec_map[c.check_id]
            md.append(f"- **{c.name}** (`{c.check_id}`): Passed ({e.duration_ms}ms)")
    else:
        md.append("- *No checks passed.*")
    md.append("")

    if failed_checks:
        md.append("### Failed Checks")
        for c in failed_checks:
            e = exec_map[c.check_id]
            md.append(f"- **{c.name}** (`{c.check_id}`): {e.status.value.upper()} (Exit {e.exit_code})")
        md.append("")

    if unrun_checks or record.unverified_areas:
        md.append("### Inconclusive / Untested Areas")
        for c in unrun_checks:
            md.append(f"- **{c.name}**: Not executed")
        for uv in record.unverified_areas:
            md.append(f"- **Requirement Gap**: {uv}")
        md.append("")

    # Findings section
    md.append("### Findings")
    if record.findings:
        for f in record.findings:
            sev_badge = f"[{f.severity.value.upper()}]"
            md.append(f"- **{sev_badge} {f.title}**: {f.description}")
            if f.evidence_ids:
                md.append(f"  *Evidence:* {', '.join([f'`{eid}`' for eid in f.evidence_ids])}")
    else:
        md.append("- No defects or security vulnerabilities identified.")
    md.append("")

    # Claim Matrix
    if record.claims:
        md.append("### Claim Verification Matrix")
        md.append("| Claim ID | Status | Claim Statement | Evidence |")
        md.append("| :--- | :--- | :--- | :--- |")
        for clm in record.claims:
            stat_icon = "SUPPORTED" if clm.status == ClaimStatus.SUPPORTED else ("FAILED" if clm.status == ClaimStatus.CONTRADICTED else "INCONCLUSIVE")
            ev_summary = f"{len(clm.supporting_evidence_ids)} sup, {len(clm.contradicting_evidence_ids)} con"
            md.append(f"| `{clm.claim_id}` | **{stat_icon}** | {clm.text} | {ev_summary} |")
        md.append("")

    # Final verdict
    verdict_str = record.overall_verdict.value.upper()
    md.append(f"### Final verdict: {verdict_str}")
    md.append("")
    for reason in record.verdict_reasons:
        md.append(f"- {reason}")
    md.append("")

    # Limitations & What was not checked
    md.append("### Stated Limitations & Unchecked Scope")
    if record.limitations:
        for lim in record.limitations:
            md.append(f"- {lim}")
    else:
        md.append("- Verification was strictly bounded to local unit/integration tests and static AST inspection.")
        md.append("- Real-world runtime concurrency and remote network conditions were not evaluated.")
    md.append("")

    # Artifact Changes section
    if record.artifacts_diff:
        added = record.artifacts_diff.get("added", [])
        modified = record.artifacts_diff.get("modified", [])
        deleted = record.artifacts_diff.get("deleted", [])
        if added or modified or deleted:
            md.append("### Artifact Changes")
            for a in added:
                md.append(f"- **Added**: `{a}`")
            for m in modified:
                md.append(f"- **Modified**: `{m}`")
            for d in deleted:
                md.append(f"- **Deleted**: `{d}`")
            md.append("")

    md.append("---")
    md.append("*Amaura Verify — Never confuse an agent's assertion with evidence that the assertion is true.*")

    return "\n".join(md)
