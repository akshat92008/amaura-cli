"""Core end-to-end verification pipeline."""

from datetime import UTC, datetime
from pathlib import Path

from amaura.config import AmauraConfig, PolicyProfile
from amaura.evidence.collector import EvidenceCollector
from amaura.evidence.graph import EvidenceGraph
from amaura.evidence.hashing import create_directory_manifest
from amaura.evidence.ledger import EvidenceLedger
from amaura.models.check import CheckExecution, CheckStatus
from amaura.models.claim import Claim
from amaura.models.finding import Finding
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
        mode: RunMode = RunMode.VERIFY,
        policy_override: PolicyProfile | None = None,
    ) -> RunRecord:
        ctx = ExecutionContext(project_dir, mode=mode)
        governor = BudgetGovernor(self.config.budget)
        collector = EvidenceCollector(ctx.run_id)
        graph = EvidenceGraph()

        # 1. Freeze task if not already frozen
        if not task.frozen:
            task.freeze()

        # 2. Derive claims from task if none provided
        effective_claims = claims if claims is not None else derive_claims_from_task(task)
        for c in effective_claims:
            graph.add_claim(c)

        # 3. Snapshot initial artifact manifest
        manifest = create_directory_manifest(project_dir)

        # 4. Plan verification checks
        planner = VerificationPlan(task, effective_claims)
        checks = planner.plan_code_project_checks(project_dir)
        for chk in checks:
            graph.add_check(chk)

        # 5. Execute verification checks in sequence
        executions: list[CheckExecution] = []
        all_findings: list[Finding] = []

        for chk in checks:
            governor.record_check_start()
            verifier = self.registry.get(chk.verifier_name)

            try:
                res = verifier.verify(project_dir, chk, collector)
                executions.append(res.execution)
                graph.add_execution(res.execution)

                for ev in res.evidence:
                    graph.add_evidence(ev)

                for f in res.findings:
                    all_findings.append(f)
                    graph.add_finding(f)

            except Exception as e:
                # Fail-closed verifier crash handling
                err_exec = CheckExecution(
                    execution_id=f"exec_err_{chk.check_id}",
                    check_id=chk.check_id,
                    status=CheckStatus.ERROR,
                    error_message=str(e),
                    end_time=datetime.now(UTC).isoformat(),
                )
                executions.append(err_exec)
                graph.add_execution(err_exec)

        # 6. Apply deterministic verdict policy
        policy_cfg = self.config.policy.model_copy()
        if policy_override:
            policy_cfg.profile = policy_override

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

        # 7. Collect git information
        git_commit, git_clean = ctx.get_git_info()

        # 8. Assemble RunRecord
        record = RunRecord(
            run_id=ctx.run_id,
            mode=mode,
            task=task,
            working_dir=str(project_dir.resolve()),
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
            limitations=[
                "Verification was bounded to local checks and recorded test coverage.",
                "Adversarial analysis evaluated vacuous assertions and explicit requirement coverage.",
            ],
            unverified_areas=verdict_res.unverified_areas,
            artifacts_manifest=manifest,
        )

        # 9. Generate markdown report and persist to ledger
        report_md = generate_markdown_report(record)
        self.ledger.save_run(record, report_markdown=report_md)

        return record
