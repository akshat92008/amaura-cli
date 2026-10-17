"""Deterministic verdict evaluator applying explicit fail-closed rules to evidence and findings."""

from typing import Optional

from amaura.config import PolicyProfile
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus, CheckType
from amaura.models.claim import Claim, ClaimStatus
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.models.run import OverallVerdict
from amaura.models.task import TaskSpec
from amaura.verdicts.policy import VerdictPolicy


class VerdictResult:
    def __init__(
        self,
        overall_verdict: OverallVerdict,
        verdict_reasons: list[str],
        updated_claims: list[Claim],
        unverified_areas: list[str],
    ):
        self.overall_verdict = overall_verdict
        self.verdict_reasons = verdict_reasons
        self.updated_claims = updated_claims
        self.unverified_areas = unverified_areas


class VerdictEvaluator:
    """Evaluates verification outcomes strictly through explicit, deterministic fail-closed rules.
    Zero-checks, unverified claims, timeouts, or critical defects can never evaluate to success.
    """

    def __init__(self, policy: VerdictPolicy):
        self.policy = policy

    def evaluate(
        self,
        task: TaskSpec,
        claims: list[Claim],
        checks: list[CheckDefinition],
        executions: list[CheckExecution],
        findings: list[Finding],
        evidence: Optional[list] = None,
    ) -> VerdictResult:
        reasons: list[str] = []
        unverified: list[str] = []
        ev_items = evidence or []

        # 0. Fail-closed on zero checks or empty executions
        if not checks or not executions:
            overall = OverallVerdict.FAILED if self.policy.profile == PolicyProfile.STRICT else OverallVerdict.INCONCLUSIVE
            reasons.append("Zero verification checks executed. An empty check suite cannot establish requirement satisfaction.")
            updated_claims = [Claim.model_validate(c.model_dump()) for c in claims]
            for uc in updated_claims:
                uc.status = ClaimStatus.NOT_CHECKED
                uc.limitations.append("No verification checks executed.")
                unverified.append(uc.text)
            return VerdictResult(overall, reasons, updated_claims, unverified)

        exec_map: dict[str, CheckExecution] = {e.check_id: e for e in executions}
        check_map: dict[str, CheckDefinition] = {c.check_id: c for c in checks}

        # 1. Identify defects and execution statuses
        critical_defects = [
            f for f in findings
            if f.finding_type == FindingType.DEFECT and f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]
        gap_findings = [
            f for f in findings
            if f.finding_type in (FindingType.TEST_GAP, FindingType.VERIFICATION_GAP)
        ]

        failed_mandatory_checks: list[str] = []
        timed_out_checks: list[str] = []
        missing_mandatory_checks: list[str] = []

        for check in checks:
            exec_item = exec_map.get(check.check_id)
            if not exec_item or exec_item.status == CheckStatus.NOT_RUN:
                if check.mandatory:
                    missing_mandatory_checks.append(check.name)
            elif exec_item.status == CheckStatus.FAILED:
                if check.mandatory:
                    failed_mandatory_checks.append(check.name)
            elif exec_item.status == CheckStatus.TIMED_OUT:
                timed_out_checks.append(check.name)
            elif exec_item.status == CheckStatus.ERROR:
                if check.mandatory:
                    failed_mandatory_checks.append(check.name)

        # 2. Update individual Claim statuses based on dedicated acceptance checks
        updated_claims: list[Claim] = []
        for claim in claims:
            # Deep clone to avoid mutating input claim objects
            claim_copy = Claim.model_validate(claim.model_dump())

            # Find checks specifically targeting this claim or requirement
            relevant_checks = [
                c for c in checks
                if c.target_claim_id == claim.claim_id
                or (claim.target_requirement_id and c.target_requirement_id == claim.target_requirement_id)
            ]
            relevant_check_ids = {c.check_id for c in relevant_checks}

            # Acceptance checks (functional behavior verification, not merely build/syntax)
            acceptance_checks = [
                c for c in relevant_checks
                if c.check_type in (CheckType.ACCEPTANCE_TEST, CheckType.TEST, CheckType.RECALCULATION)
            ]

            # Findings linked to this claim
            claim_findings = [
                f for f in findings
                if f.claim_id == claim.claim_id
                or (claim.target_requirement_id and f.check_id in relevant_check_ids)
            ]
            claim_defects = [
                f for f in claim_findings
                if f.finding_type == FindingType.DEFECT and f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
            ]
            claim_gaps = [
                f for f in claim_findings
                if f.finding_type in (FindingType.TEST_GAP, FindingType.VERIFICATION_GAP)
            ]

            has_failed_check = any(
                exec_map.get(c.check_id) and exec_map[c.check_id].status in (CheckStatus.FAILED, CheckStatus.ERROR, CheckStatus.TIMED_OUT)
                for c in relevant_checks
            )

            has_passed_acceptance = any(
                exec_map.get(c.check_id) and exec_map[c.check_id].status == CheckStatus.PASSED
                for c in acceptance_checks
            )

            # Match evidence
            supporting_ev = [
                ev.evidence_id for ev in ev_items
                if (ev.claim_id == claim.claim_id or ev.check_id in relevant_check_ids)
                and exec_map.get(ev.check_id) and exec_map[ev.check_id].status == CheckStatus.PASSED
            ]
            contradicting_ev = [
                ev.evidence_id for ev in ev_items
                if (ev.claim_id == claim.claim_id or ev.check_id in relevant_check_ids)
                and exec_map.get(ev.check_id) and exec_map[ev.check_id].status in (CheckStatus.FAILED, CheckStatus.ERROR)
            ]

            claim_copy.supporting_evidence_ids = supporting_ev
            claim_copy.contradicting_evidence_ids = contradicting_ev

            if claim_defects or has_failed_check:
                claim_copy.status = ClaimStatus.CONTRADICTED
                claim_copy.limitations.append("Contradicted by observed test failure or defect.")
            elif claim_gaps or not acceptance_checks or not has_passed_acceptance:
                claim_copy.status = ClaimStatus.INCONCLUSIVE
                claim_copy.limitations.append("Insufficient evidence: missing or unexecuted dedicated acceptance test.")
                unverified.append(claim.text)
            else:
                claim_copy.status = ClaimStatus.SUPPORTED

            updated_claims.append(claim_copy)

        # 3. Formulate overall verdict with fail-closed rules
        # Precedence: FAILED > INCONCLUSIVE > PASSED

        # Case A: Critical failures, failed mandatory checks, or contradicted claims
        any_claim_contradicted = any(c.status == ClaimStatus.CONTRADICTED for c in updated_claims)
        if failed_mandatory_checks or critical_defects or any_claim_contradicted:
            overall = OverallVerdict.FAILED
            for chk_name in failed_mandatory_checks:
                reasons.append(f"Mandatory verification check failed: '{chk_name}'")
            for f in critical_defects:
                reasons.append(f"Critical defect: {f.title} ({f.description[:120]})")
            if any_claim_contradicted and not reasons:
                reasons.append("One or more claims were contradicted by observed evidence.")

        # Case B: Timed out mandatory checks (fail-closed)
        elif timed_out_checks:
            overall = OverallVerdict.FAILED
            for chk_name in timed_out_checks:
                reasons.append(f"Mandatory check exceeded budget and timed out: '{chk_name}'")

        # Case C: Missing mandatory checks or untested requirement gaps
        elif missing_mandatory_checks or gap_findings:
            if self.policy.profile == PolicyProfile.STRICT:
                overall = OverallVerdict.FAILED
                if missing_mandatory_checks:
                    reasons.append(f"Strict policy failure: Missing mandatory checks: {', '.join(missing_mandatory_checks)}")
                for g in gap_findings:
                    reasons.append(f"Strict policy failure: {g.title} - {g.description[:120]}")
            else:
                overall = OverallVerdict.INCONCLUSIVE
                if missing_mandatory_checks:
                    reasons.append(f"Mandatory checks were not executed: {', '.join(missing_mandatory_checks)}")
                for g in gap_findings:
                    reasons.append(f"Verification gap: {g.title} - {g.description[:120]}")

        # Case D: Claims check: all claims corresponding to mandatory requirements must be SUPPORTED
        elif any(c.status in (ClaimStatus.INCONCLUSIVE, ClaimStatus.NOT_CHECKED) for c in updated_claims):
            inconclusive_claims = [c.text for c in updated_claims if c.status in (ClaimStatus.INCONCLUSIVE, ClaimStatus.NOT_CHECKED)]
            if self.policy.profile == PolicyProfile.STRICT:
                overall = OverallVerdict.FAILED
                reasons.append(f"Strict policy failure: Unverified claims: {'; '.join(inconclusive_claims[:3])}")
            else:
                overall = OverallVerdict.INCONCLUSIVE
                reasons.append(f"Unverified claims remaining: {'; '.join(inconclusive_claims[:3])}")

        # Case E: All passed cleanly
        else:
            overall = OverallVerdict.PASSED
            reasons.append("All mandatory acceptance and quality checks passed with supporting evidence.")

        return VerdictResult(
            overall_verdict=overall,
            verdict_reasons=reasons,
            updated_claims=updated_claims,
            unverified_areas=unverified,
        )
