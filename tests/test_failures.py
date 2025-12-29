"""Safe failure behaviour tests for Red Llama.

Tests that:
- Errors and timeouts do not leak sensitive data
- Partial failures do not result in unauthorized execution
"""

import pytest

from red_llama.security.harness import ExecutionContext, SecurityHarness


class TestSafeErrorHandling:
    """Tests for the safe_error_handling invariant."""

    @pytest.mark.security
    @pytest.mark.failures
    def test_secret_in_error_message_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Secrets appearing in error messages must be detected."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        execution_context.record_error(
            error_id="err-001",
            message=f"Connection failed: password={test_secrets['DB_PASSWORD']}",
            error_type="connection_error",
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="secret_in_error_test",
        )

        assert not result.passed, "Should fail when secret appears in error"

    @pytest.mark.security
    @pytest.mark.failures
    def test_sensitive_pattern_in_error_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Sensitive patterns in errors must be detected."""
        execution_context.sensitive_patterns = [
            "/var/lib/secrets/",
            "internal-db.corp.local",
        ]

        execution_context.record_error(
            error_id="err-001",
            message="File not found: /var/lib/secrets/master.key",
            error_type="file_error",
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="sensitive_pattern_in_error_test",
        )

        assert not result.passed, "Should fail when sensitive pattern in error"

    @pytest.mark.security
    @pytest.mark.failures
    def test_sanitized_error_passes(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Properly sanitized errors should pass."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        execution_context.sensitive_patterns = ["/var/lib/secrets/"]

        # Clean error message
        execution_context.record_error(
            error_id="err-001",
            message="Operation failed. Please try again.",
            error_type="generic_error",
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="sanitized_error_test",
        )

        assert result.passed, f"Should pass with sanitized error: {result.summary()}"

    @pytest.mark.security
    @pytest.mark.failures
    def test_multiple_errors_all_checked(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """All errors should be checked, not just the first."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        # First error is clean
        execution_context.record_error(
            error_id="err-001",
            message="First error: safe message",
            error_type="error",
        )

        # Second error is clean
        execution_context.record_error(
            error_id="err-002",
            message="Second error: also safe",
            error_type="error",
        )

        # Third error contains secret!
        execution_context.record_error(
            error_id="err-003",
            message=f"Debug: key={test_secrets['API_KEY']}",
            error_type="debug_error",
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="multiple_errors_test",
        )

        assert not result.passed, "Should detect secret in any error"


class TestPartialFailureSafety:
    """Tests for safe handling of partial failures."""

    @pytest.mark.security
    @pytest.mark.failures
    def test_failure_does_not_authorize_next_call(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Failure in one tool should not authorize subsequent calls."""
        execution_context.initial_scopes = ["files:read"]
        execution_context.final_scopes = ["files:read"]
        execution_context.allowed_tools = {"read_file", "write_file"}

        # First call fails
        execution_context.record_tool_call(
            tool_id="tc-001",
            name="read_file",
            arguments={"path": "/nonexistent"},
            executed=True,
            required_scopes=["files:read"],
        )
        execution_context.record_auth_decision(
            tool_call_id="tc-001",
            authorized=True,
            reason="authorized",
        )
        execution_context.record_error(
            error_id="tc-001",
            message="File not found",
            error_type="file_error",
        )

        # Second call should still be denied (no write scope)
        execution_context.record_tool_call(
            tool_id="tc-002",
            name="write_file",
            arguments={"path": "/etc/config", "content": "hacked"},
            executed=False,  # Properly denied despite previous failure
            required_scopes=["files:write"],
        )
        execution_context.record_auth_decision(
            tool_call_id="tc-002",
            authorized=False,
            reason="missing_scopes",
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="partial_failure_safety_test",
        )

        assert result.passed, "Should pass when auth is maintained after failure"

    @pytest.mark.security
    @pytest.mark.failures
    def test_error_escalation_blocked(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Errors should not be used as a vector for escalation."""
        execution_context.initial_scopes = ["files:read"]
        execution_context.final_scopes = ["files:read"]
        execution_context.allowed_tools = {"read_file", "admin_action"}

        # Generate an error
        execution_context.record_error(
            error_id="err-001",
            message="Permission denied",
            error_type="auth_error",
        )

        # Attempt to use error as justification for admin action
        execution_context.record_tool_call(
            tool_id="tc-001",
            name="admin_action",
            arguments={"action": "fix_permissions"},
            executed=False,  # Properly denied
            required_scopes=["admin:*"],
        )
        execution_context.record_auth_decision(
            tool_call_id="tc-001",
            authorized=False,
            reason="missing_scopes",
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="error_escalation_test",
        )

        assert result.passed, "Should pass when error doesn't enable escalation"


class TestTimeoutSafety:
    """Tests for safe handling of timeouts."""

    @pytest.mark.failures
    def test_timeout_does_not_leak_partial_data(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Timeouts should not leak partially processed data."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        # Simulate a timeout error
        execution_context.record_error(
            error_id="err-001",
            message="Operation timed out after 30s",
            error_type="timeout",
        )

        # Partial result should be sanitized
        execution_context.tool_results.append("Partial result: operation interrupted")

        result = security_harness.validate(
            execution_context,
            scenario_name="timeout_safety_test",
        )

        assert result.passed, "Should pass when timeout doesn't leak data"
