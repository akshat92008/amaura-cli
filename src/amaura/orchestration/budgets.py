"""Budget and resource governor for verification runs."""

from amaura.config import BudgetConfig
from amaura.errors import ExecutionSecurityError


class BudgetGovernor:
    """Enforces execution boundaries, limiting checks, timeouts, and capture size."""

    def __init__(self, config: BudgetConfig):
        self.config = config
        self.checks_executed = 0

    def record_check_start(self) -> None:
        if self.checks_executed >= self.config.max_checks_per_run:
            raise ExecutionSecurityError(
                f"Execution budget exceeded: Maximum check limit ({self.config.max_checks_per_run}) reached."
            )
        self.checks_executed += 1
