from typing import Optional

from amaura.config import PolicyProfile
from amaura.models.check import CheckDefinition, CheckExecution, CheckStatus
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
    """Evaluates verification outcomes strictly through explicit, deterministic rules.
    Never relies on unexplained confidence scores or majority votes.
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

        # Index executions by check_id
        exec_map: dict[str, CheckExecution] = {e.check_id: e for e in executions}
        check_map: dict[str, CheckDefinition] = {c.check_id: c for c in checks}

        # 1. Check for critical defects and unmet mandatory requirements
        critical_findings = [f for f in findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) and f.is_blocking]
        gap_findings = [f for f in findings if f.finding_type in (FindingType.TEST_GAP, FindingType.VERIFICATION_GAP)]

        # 2. Check execution statuses for mandatory checks
        failed_mandatory_checks: list[str] = []
        timed_out_checks: list[str] = []
        missing_checks: list[str] = []

        for check in checks:
            exec_item = exec_map.get(check.check_id)
            if not exec_item or exec_item.status == CheckStatus.NOT_RUN:
                if check.mandatory:
                    missing_checks.append(check.name)
            elif exec_item.status == CheckStatus.FAILED:
                if check.mandatory:
                    failed_mandatory_checks.append(check.name)
            elif exec_item.status == CheckStatus.TIMED_OUT:
                timed_out_checks.append(check.name)
            elif exec_item.status == CheckStatus.ERROR:
                if check.mandatory:
                    failed_mandatory_checks.append(check.name)

        # 3. Update individual Claim statuses based on evidence
        updated_claims: list[Claim] = []
        for claim in claims:
            # Find checks for this claim
            relevant_checks = [
                c for c in checks
                if c.target_claim_id == claim.claim_id
                or (claim.target_requirement_id and c.target_requirement_id == claim.target_requirement_id)
            ]
            relevant_check_ids = {c.check_id for c in relevant_checks}

            # Find findings for this claim
            claim_findings = [
                f for f in findings
                if f.claim_id == claim.claim_id
                or (claim.target_requirement_id and f.check_id in relevant_check_ids)
            ]

            blocking_claim_findings = [
                f for f in claim_findings
                if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) and f.finding_type == FindingType.DEFECT
            ]

            gap_claim_findings = [
                f for f in claim_findings
                if f.finding_type in (FindingType.TEST_GAP, FindingType.VERIFICATION_GAP)
            ]

            has_failed_check = any(
                exec_map.get(c.check_id) and exec_map[c.check_id].status in (CheckStatus.FAILED, CheckStatus.ERROR)
                for c in relevant_checks
            )

            has_passed_check = any(
                exec_map.get(c.check_id) and exec_map[c.check_id].status == CheckStatus.PASSED
                for c in relevant_checks
            )

            # Match evidence items
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

            claim_copy = claim.model_copy()
            claim_copy.supporting_evidence_ids = supporting_ev
            claim_copy.contradicting_evidence_ids = contradicting_ev

            if blocking_claim_findings or has_failed_check:
                claim_copy.status = ClaimStatus.CONTRADICTED
                claim_copy.limitations.append("Contradicted by observed test failure or defect.")
            elif gap_claim_findings or not relevant_checks or not has_passed_check:
                claim_copy.status = ClaimStatus.INCONCLUSIVE
                claim_copy.limitations.append("Insufficient evidence or requirement coverage gap.")
                unverified.append(claim.text)
            else:
                claim_copy.status = ClaimStatus.SUPPORTED

            updated_claims.append(claim_copy)

        # 4. Formulate overall verdict with fail-closed rules
        if failed_mandatory_checks:
            overall = OverallVerdict.FAILED
            for chk_name in failed_mandatory_checks:
                reasons.append(f"Mandatory verification check failed: '{chk_name}'")
            if critical_findings:
                reasons.append(f"{len(critical_findings)} blocking defect(s) detected during verification.")

        elif timed_out_checks and self.policy.config.fail_closed_on_timeout:
            overall = OverallVerdict.FAILED
            for chk_name in timed_out_checks:
                reasons.append(f"Verification check exceeded budget and timed out: '{chk_name}'")

        elif critical_findings:
            overall = OverallVerdict.FAILED
            for f in critical_findings:
                reasons.append(f"Blocking finding: {f.title} ({f.description[:120]})")

        elif missing_checks and self.policy.config.fail_closed_on_missing_check:
            if self.policy.profile == PolicyProfile.STRICT:
                overall = OverallVerdict.FAILED
                reasons.append(f"Missing mandatory verification checks in strict mode: {', '.join(missing_checks)}")
            else:
                overall = OverallVerdict.INCONCLUSIVE
                reasons.append(f"Mandatory checks were not executed: {', '.join(missing_checks)}")

        elif gap_findings:
            # We detected a test gap or vacuous test (e.g. tests pass but an acceptance requirement is untested)
            if self.policy.profile == PolicyProfile.STRICT:
                overall = OverallVerdict.FAILED
                for g in gap_findings:
                    reasons.append(f"Strict policy failure: {g.title} - {g.description}")
            else:
                overall = OverallVerdict.INCONCLUSIVE
                for g in gap_findings:
                    reasons.append(f"Verification gap: {g.title} - {g.description}")

        else:
            # All mandatory checks passed, no blocking defects or test gaps
            overall = OverallVerdict.PASSED
            reasons.append("All mandatory acceptance and quality checks passed with supporting evidence.")

        return VerdictResult(
            overall_verdict=overall,
            verdict_reasons=reasons,
            updated_claims=updated_claims,
            unverified_areas=unverified,
        )
