"""Security harness for Red Llama.

The harness orchestrates security invariant checking and provides
a unified interface for executing and validating agent scenarios.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.table import Table

from red_llama.security.invariants import (
    Blame,
    InvariantResult,
    InvariantType,
    LLMAttemptedUnauthorizedAction,
    NoPrivilegeEscalation,
    NoSecretsInOutput,
    NoUnauthorizedToolExecution,
    SafeErrorHandling,
    SecurityInvariant,
    Severity,
    UncensoredLLMCompliance,
    UnknownToolsDenied,
)
from red_llama.security.sanitizer import SecretSanitizer

logger = logging.getLogger(__name__)


@dataclass
class ExecutionContext:
    """Context for a single agent execution that will be validated."""

    # Tool execution tracking
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    auth_decisions: list[dict[str, Any]] = field(default_factory=list)

    # Scope tracking
    initial_scopes: list[str] = field(default_factory=list)
    final_scopes: list[str] = field(default_factory=list)
    allowed_tools: set[str] = field(default_factory=set)

    # Output tracking
    prompts: list[str] = field(default_factory=list)
    responses: list[str] = field(default_factory=list)
    tool_results: list[Any] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)

    # Secret tracking
    secrets: list[dict[str, str]] = field(default_factory=list)
    sensitive_patterns: list[str] = field(default_factory=list)

    # Error tracking
    errors: list[dict[str, Any]] = field(default_factory=list)

    # Scenario flags
    expect_compliance: bool = False  # For uncensored LLM testing

    def to_dict(self) -> dict[str, Any]:
        """Convert context to a dictionary for invariant checking."""
        return {
            "tool_calls": self.tool_calls,
            "auth_decisions": self.auth_decisions,
            "initial_scopes": self.initial_scopes,
            "final_scopes": self.final_scopes,
            "allowed_tools": self.allowed_tools,
            "outputs": {
                "prompts": self.prompts,
                "responses": self.responses,
                "tool_results": self.tool_results,
                "logs": self.logs,
            },
            "secrets": self.secrets,
            "sensitive_patterns": self.sensitive_patterns,
            "errors": self.errors,
            "expect_compliance": self.expect_compliance,
        }

    def record_tool_call(
        self,
        tool_id: str,
        name: str,
        arguments: dict[str, Any],
        executed: bool = False,
        required_scopes: list[str] | None = None,
    ) -> None:
        """Record a tool call attempt."""
        self.tool_calls.append(
            {
                "id": tool_id,
                "name": name,
                "arguments": arguments,
                "executed": executed,
                "required_scopes": required_scopes or [],
            }
        )

    def record_auth_decision(
        self,
        tool_call_id: str,
        authorized: bool,
        reason: str = "",
        scopes_checked: list[str] | None = None,
    ) -> None:
        """Record an authorization decision."""
        self.auth_decisions.append(
            {
                "tool_call_id": tool_call_id,
                "authorized": authorized,
                "reason": reason,
                "scopes_checked": scopes_checked or [],
            }
        )

    def record_error(
        self,
        error_id: str,
        message: str,
        error_type: str = "unknown",
    ) -> None:
        """Record an error."""
        self.errors.append(
            {
                "id": error_id,
                "message": message,
                "type": error_type,
            }
        )

    def add_secret(self, name: str, value: str) -> None:
        """Register a secret that should never appear in outputs."""
        self.secrets.append({"name": name, "value": value})


@dataclass
class HarnessResult:
    """Result of running the security harness."""

    passed: bool
    invariant_results: list[InvariantResult]
    critical_failures: list[InvariantResult]
    scenario_name: str = ""

    @property
    def total_checks(self) -> int:
        return len(self.invariant_results)

    @property
    def passed_checks(self) -> int:
        return sum(1 for r in self.invariant_results if r.passed)

    @property
    def failed_checks(self) -> int:
        return sum(1 for r in self.invariant_results if not r.passed)

    def summary(self) -> str:
        """Generate a summary string."""
        status = "PASSED" if self.passed else "FAILED"
        return (
            f"[{status}] {self.scenario_name}: "
            f"{self.passed_checks}/{self.total_checks} checks passed"
        )


class SecurityHarness:
    """
    Main security harness for executing and validating agent scenarios.

    The harness:
    1. Maintains a set of security invariants to check
    2. Provides context tracking for agent executions
    3. Validates all invariants after execution
    4. Reports results with clear pass/fail status
    """

    def __init__(
        self,
        invariants: list[SecurityInvariant] | None = None,
        fail_fast: bool = True,
    ) -> None:
        """
        Initialize the security harness.

        Args:
            invariants: List of security invariants to check.
                       If None, uses all standard invariants.
            fail_fast: If True, stop checking after first critical failure.
        """
        self._invariants: list[SecurityInvariant] = invariants or self._default_invariants()
        self._fail_fast = fail_fast
        self._sanitizer = SecretSanitizer()
        self._console = Console()

    def _default_invariants(self) -> list[SecurityInvariant]:
        """Get the default set of security invariants."""
        return [
            NoUnauthorizedToolExecution(),
            UnknownToolsDenied(),
            NoSecretsInOutput(),
            NoPrivilegeEscalation(),
            SafeErrorHandling(),
            LLMAttemptedUnauthorizedAction(),
            UncensoredLLMCompliance(),
        ]

    def add_invariant(self, invariant: SecurityInvariant) -> None:
        """Add a custom invariant to the harness."""
        self._invariants.append(invariant)

    def create_context(self) -> ExecutionContext:
        """Create a new execution context for tracking."""
        return ExecutionContext()

    def validate(
        self,
        context: ExecutionContext,
        scenario_name: str = "unnamed",
    ) -> HarnessResult:
        """
        Validate all security invariants against the execution context.

        Args:
            context: The execution context to validate
            scenario_name: Name of the scenario for reporting

        Returns:
            HarnessResult with all invariant check results
        """
        results: list[InvariantResult] = []
        critical_failures: list[InvariantResult] = []
        context_dict = context.to_dict()

        for invariant in self._invariants:
            try:
                result = invariant.check(context_dict)
                results.append(result)

                if result.is_critical_failure:
                    critical_failures.append(result)
                    logger.error(
                        "CRITICAL FAILURE: %s — %s",
                        invariant.name,
                        result.message,
                    )
                    if self._fail_fast:
                        break
                elif not result.passed:
                    logger.warning(
                        "FAILURE: %s — %s",
                        invariant.name,
                        result.message,
                    )
                else:
                    logger.debug("PASS: %s", invariant.name)

            except Exception as e:
                # Invariant check itself failed — treat as failure
                error_result = InvariantResult(
                    passed=False,
                    invariant_name=invariant.name,
                    invariant_type=invariant.invariant_type,
                    severity=Severity.HIGH,
                    message=f"Invariant check raised exception: {e}",
                    details={"exception": str(e)},
                )
                results.append(error_result)
                logger.error("Invariant check failed: %s — %s", invariant.name, e)

        passed = len(critical_failures) == 0 and all(
            r.passed or r.severity in (Severity.MEDIUM, Severity.LOW) for r in results
        )

        return HarnessResult(
            passed=passed,
            invariant_results=results,
            critical_failures=critical_failures,
            scenario_name=scenario_name,
        )

    def print_results(self, result: HarnessResult) -> None:
        """Print formatted results to console."""
        table = Table(title=f"Security Check Results: {result.scenario_name}")
        table.add_column("Invariant", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Severity", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Message")

        for inv_result in result.invariant_results:
            status_style = "green" if inv_result.passed else "red"
            status = "✓ PASS" if inv_result.passed else "✗ FAIL"

            table.add_row(
                inv_result.invariant_name,
                inv_result.invariant_type.name,
                inv_result.severity.value,
                f"[{status_style}]{status}[/{status_style}]",
                inv_result.message,
            )

        self._console.print(table)

        if result.passed:
            self._console.print(
                f"\n[bold green]✓ ALL CHECKS PASSED[/bold green] "
                f"({result.passed_checks}/{result.total_checks})"
            )
        else:
            self._console.print(
                f"\n[bold red]✗ SECURITY CHECKS FAILED[/bold red] "
                f"({result.failed_checks} failures, "
                f"{len(result.critical_failures)} critical)"
            )

    def get_invariants_by_type(self, inv_type: InvariantType) -> list[SecurityInvariant]:
        """Get all invariants of a specific type."""
        return [i for i in self._invariants if i.invariant_type == inv_type]

    @property
    def sanitizer(self) -> SecretSanitizer:
        """Get the secret sanitizer."""
        return self._sanitizer

    @property
    def invariants(self) -> list[SecurityInvariant]:
        """Get all registered security invariants."""
        return self._invariants.copy()

