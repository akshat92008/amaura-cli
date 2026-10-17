"""Core end-to-end verification pipeline."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

from amaura.config import AmauraConfig, PolicyProfile
from amaura.errors import ExecutionSecurityError
from amaura.evidence.collector import EvidenceCollector
from amaura.evidence.graph import EvidenceGraph
from amaura.evidence.hashing import compute_artifact_diff, create_directory_manifest
from amaura.evidence.ledger import EvidenceLedger
from amaura.models.check import CheckExecution, CheckStatus
from amaura.models.claim import Claim
from amaura.models.finding import Finding, FindingSeverity, FindingType
from amaura.models.run import RunMode, RunRecord
from amaura.models.task import TaskSpec
from amaura.orchestration.budgets import BudgetGovernor
from amaura.orchestration.state import ExecutionContext
from amaura.planning.claims import derive_claims_from_task
from amaura.planning.verification_plan import VerificationPlan
from amaura.reporting.markdown import generate_markdown_report
from amaura.verdicts.evaluator import VerdictEvaluator
from amaura.verdicts.policy import VerdictPolicy
from amaura.verifiers.registry import VerifierRegistry


class VerificationPipeline:
    """End-to-end verification orchestrator maintaining immutable evidence chains."""

    def __init__(self, config: AmauraConfig | None = None):
        self.config = config or AmauraConfig()
        self.registry = VerifierRegistry(self.config)
        self.ledger = EvidenceLedger(Path(self.config.runs_dir))

    def run(
        self,
        project_dir: Path,
        task: TaskSpec,
        claims: list[Claim] | None = None,
        source_dir: Path | None = None,
        mode: RunMode = RunMode.VERIFY,
        policy_override: PolicyProfile | None = None,
        extra_limitations: list[str] | None = None,
    ) -> RunRecord:
        ctx = ExecutionContext(project_dir, source_dir=source_dir, mode=mode)
        governor = BudgetGovernor(self.config.budget)
        collector = EvidenceCollector(ctx.run_id)
        graph = EvidenceGraph()

        # 1. Freeze task if not already frozen, and strictly verify task hash (B6)
        if not task.frozen:
            task.freeze()
        if not task.verify_hash():
            from amaura.errors import TaskSpecificationError
            raise TaskSpecificationError("Task specification integrity check failed: task has invalid hash or was modified.")

        # 2. Derive claims from task if none provided
        effective_claims = claims if claims is not None else derive_claims_from_task(task)
        for c in effective_claims:
            graph.add_claim(c)

        # 3. Snapshot initial artifact manifest (B11)
        initial_manifest = create_directory_manifest(project_dir)

        # 4. Plan verification checks
        planner = VerificationPlan(task, effective_claims)
        checks = planner.plan_checks(project_dir)
        for chk in checks:
            graph.add_check(chk)

        # 5. Execute verification checks in sequence
        executions: list[CheckExecution] = []
        all_findings: list[Finding] = []

        budget_exhausted = False
        for chk in checks:
            if budget_exhausted:
                # D1: Record remaining checks cleanly as NOT_RUN instead of aborting without record
                not_run_exec = CheckExecution(
                    execution_id=f"exec_budget_{chk.check_id}",
                    check_id=chk.check_id,
                    status=CheckStatus.NOT_RUN,
                    error_message="Skipped: Execution check budget reached",
                    end_time=datetime.now(UTC).isoformat(),
                )
                executions.append(not_run_exec)
                graph.add_execution(not_run_exec)
                continue

            try:
                # D1 & D2: governor and registry resolution inside try block
                governor.record_check_start()
                verifier = self.registry.get(chk.verifier_name)

                res = verifier.verify(project_dir, chk, collector)
                executions.append(res.execution)
                graph.add_execution(res.execution)

                for ev in res.evidence:
                    graph.add_evidence(ev)

                for f in res.findings:
                    all_findings.append(f)
                    graph.add_finding(f)

            except ExecutionSecurityError as e:
                # D1: Budget limit reached or execution security violation
                err_exec = CheckExecution(
                    execution_id=f"exec_err_{chk.check_id}",
                    check_id=chk.check_id,
                    status=CheckStatus.ERROR,
                    error_message=str(e),
                    end_time=datetime.now(UTC).isoformat(),
                )
                executions.append(err_exec)
                graph.add_execution(err_exec)

                if "budget exceeded" in str(e).lower():
                    budget_exhausted = True
                    all_findings.append(
                        Finding(
                            finding_id=f"find_budget_{uuid.uuid4().hex[:8]}",
                            check_id=chk.check_id,
                            claim_id=chk.target_claim_id,
                            title="Execution Budget Exceeded",
                            description=str(e),
                            finding_type=FindingType.VERIFICATION_GAP,
                            severity=FindingSeverity.HIGH,
                            is_blocking=True,
                        )
                    )
                else:
                    all_findings.append(
                        Finding(
                            finding_id=f"find_err_{uuid.uuid4().hex[:8]}",
                            check_id=chk.check_id,
                            claim_id=chk.target_claim_id,
                            title=f"Security Violation During Check ({chk.name})",
                            description=str(e),
                            finding_type=FindingType.SECURITY_RISK,
                            severity=FindingSeverity.CRITICAL,
                            is_blocking=True,
                        )
                    )

            except Exception as e:
                # Fail-closed verifier crash handling (D2)
                err_exec = CheckExecution(
                    execution_id=f"exec_err_{chk.check_id}",
                    check_id=chk.check_id,
                    status=CheckStatus.ERROR,
                    error_message=str(e),
                    end_time=datetime.now(UTC).isoformat(),
                )
                executions.append(err_exec)
                graph.add_execution(err_exec)

                all_findings.append(
                    Finding(
                        finding_id=f"find_err_{uuid.uuid4().hex[:8]}",
                        check_id=chk.check_id,
                        claim_id=chk.target_claim_id,
                        title=f"Check Execution Failure ({chk.name})",
                        description=f"Verifier error during '{chk.name}': {e!s}",
                        finding_type=FindingType.VERIFICATION_GAP,
                        severity=FindingSeverity.HIGH,
                        is_blocking=True,
                    )
                )

        # 6. Apply deterministic verdict policy
        policy_cfg = self.config.policy.model_copy()
        if policy_override:
            policy_cfg.profile = policy_override

        # 7. Collect git information and enforce require_clean_git (B10)
        git_commit, git_clean = ctx.get_git_info()
        if policy_cfg.require_clean_git and git_clean is not True:
            reason = (
                "Working tree has uncommitted modifications"
                if git_clean is False
                else "Target is not a valid git repository"
            )
            git_finding = Finding(
                finding_id=f"find_git_clean_{uuid.uuid4().hex[:8]}",
                check_id="chk_git_clean",
                title="Git Repository Not Clean",
                description=f"Policy mandates require_clean_git=True, but: {reason}.",
                severity=FindingSeverity.CRITICAL,
                finding_type=FindingType.DEFECT,
            )
            all_findings.append(git_finding)
            graph.add_finding(git_finding)

        policy = VerdictPolicy(policy_cfg)
        evaluator = VerdictEvaluator(policy)
        verdict_res = evaluator.evaluate(
            task=task,
            claims=effective_claims,
            checks=checks,
            executions=executions,
            findings=all_findings,
            evidence=collector.items,
        )

        # 8. Snapshot final manifest and compute before/after artifact diff (B11)
        final_manifest = create_directory_manifest(project_dir)
        artifacts_diff = compute_artifact_diff(initial_manifest, final_manifest)

        # 9. Assemble RunRecord
        limitations = [
            "Verification was bounded to local checks and recorded test coverage.",
            "Adversarial analysis evaluated vacuous assertions and explicit requirement coverage.",
        ]
        if extra_limitations:
            limitations.extend(extra_limitations)

        record = RunRecord(
            run_id=ctx.run_id,
            mode=mode,
            task=task,
            working_dir=str((source_dir or project_dir).resolve()),
            git_commit=git_commit,
            git_clean=git_clean,
            claims=verdict_res.updated_claims,
            checks=checks,
            executions=executions,
            evidence=collector.items,
            findings=all_findings,
            overall_verdict=verdict_res.overall_verdict,
            verdict_reasons=verdict_res.verdict_reasons,
            policy_applied=policy_cfg.profile.value,
            limitations=limitations,
            unverified_areas=verdict_res.unverified_areas,
            artifacts_manifest=final_manifest,
            artifacts_diff=artifacts_diff,
        )

        # 10. Generate markdown report and persist once to immutable ledger (B3, B7)
        report_md = generate_markdown_report(record)
        self.ledger.save_run(record, report_markdown=report_md, graph_dict=graph.to_dict())

        return record
