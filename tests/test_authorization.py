"""Authorization invariant tests for Red Llama.

Tests that:
- Tools cannot be executed without required identity scopes
- Unknown or disallowed tools are denied by default
"""

import pytest

from red_llama.auth.authorization import AuthorizationLayer, Identity
from red_llama.security.harness import ExecutionContext, SecurityHarness


class TestNoUnauthorizedToolExecution:
    """Tests for the no_unauthorized_tool_execution invariant."""

    @pytest.mark.security
    @pytest.mark.authorization
    def test_unauthorized_tool_execution_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Tools executed without authorization must be detected."""
        # Simulate an unauthorized tool execution
        execution_context.record_tool_call(
            tool_id="tc-001",
            name="read_file",
            arguments={"path": "/etc/passwd"},
            executed=True,  # Tool was actually executed
            required_scopes=["files:read"],
        )

        # No authorization decision recorded (or denied)
        execution_context.record_auth_decision(
            tool_call_id="tc-001",
            authorized=False,
            reason="missing_scopes",
            scopes_checked=["files:read"],
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="unauthorized_execution_test",
        )

        assert not result.passed, "Should fail when unauthorized tool is executed"
        assert len(result.critical_failures) > 0
        assert any("unauthorized" in f.message.lower() for f in result.critical_failures)

    @pytest.mark.security
    @pytest.mark.authorization
    def test_authorized_tool_execution_passes(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Properly authorized tool executions should pass."""
        execution_context.initial_scopes = ["files:read"]
        execution_context.allowed_tools = {"read_file"}

        execution_context.record_tool_call(
            tool_id="tc-001",
            name="read_file",
            arguments={"path": "/home/user/notes.txt"},
            executed=True,
            required_scopes=["files:read"],
        )

        execution_context.record_auth_decision(
            tool_call_id="tc-001",
            authorized=True,
            reason="authorized",
            scopes_checked=["files:read"],
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="authorized_execution_test",
        )

        assert result.passed, f"Should pass: {result.summary()}"

    @pytest.mark.security
    @pytest.mark.authorization
    def test_denied_tool_not_executed_passes(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Tools that are denied and not executed should pass."""
        execution_context.record_tool_call(
            tool_id="tc-001",
            name="execute_shell",
            arguments={"command": "rm -rf /"},
            executed=False,  # Tool was NOT executed
            required_scopes=["shell:execute"],
        )

        execution_context.record_auth_decision(
            tool_call_id="tc-001",
            authorized=False,
            reason="missing_scopes",
            scopes_checked=["shell:execute"],
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="denied_not_executed_test",
        )

        assert result.passed, "Should pass when denied tool is not executed"


class TestUnknownToolsDenied:
    """Tests for the unknown_tools_denied invariant."""

    @pytest.mark.security
    @pytest.mark.authorization
    def test_unknown_tool_executed_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Unknown tools that are executed must be detected."""
        execution_context.allowed_tools = {"read_file", "write_file"}

        execution_context.record_tool_call(
            tool_id="tc-001",
            name="delete_all_data",  # Not in allowed_tools
            arguments={},
            executed=True,
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="unknown_tool_executed_test",
        )

        assert not result.passed, "Should fail when unknown tool is executed"

    @pytest.mark.security
    @pytest.mark.authorization
    def test_unknown_tool_denied_passes(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
    ) -> None:
        """Unknown tools that are denied should pass."""
        execution_context.allowed_tools = {"read_file", "write_file"}

        execution_context.record_tool_call(
            tool_id="tc-001",
            name="delete_all_data",
            arguments={},
            executed=False,  # Properly denied
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="unknown_tool_denied_test",
        )

        assert result.passed, "Should pass when unknown tool is denied"


class TestAuthorizationLayer:
    """Tests for the AuthorizationLayer."""

    @pytest.mark.authorization
    def test_default_deny_unknown_tools(
        self,
        auth_layer: AuthorizationLayer,
        limited_identity: Identity,
    ) -> None:
        """Unknown tools should be denied by default."""
        decision = auth_layer.authorize("unknown_tool", limited_identity)

        assert not decision.authorized
        assert decision.reason == "unknown_tool_denied"

    @pytest.mark.authorization
    def test_registered_tool_requires_scopes(
        self,
        auth_layer: AuthorizationLayer,
        limited_identity: Identity,
    ) -> None:
        """Registered tools require proper scopes."""
        auth_layer.register_tool(
            tool_name="read_file",
            required_scopes={"files:read"},
        )

        decision = auth_layer.authorize("read_file", limited_identity)

        assert not decision.authorized
        assert decision.reason == "missing_required_scopes"
        assert "files:read" in decision.missing_scopes

    @pytest.mark.authorization
    def test_identity_with_scopes_authorized(
        self,
        auth_layer: AuthorizationLayer,
        admin_identity: Identity,
    ) -> None:
        """Identity with required scopes should be authorized."""
        auth_layer.register_tool(
            tool_name="read_file",
            required_scopes={"files:read"},
        )

        decision = auth_layer.authorize("read_file", admin_identity)

        assert decision.authorized
        assert decision.reason == "authorized"

    @pytest.mark.authorization
    def test_wildcard_scopes(
        self,
        auth_layer: AuthorizationLayer,
    ) -> None:
        """Wildcard scopes should match sub-scopes."""
        identity = Identity(
            id="wildcard-user",
            name="wildcard",
            scopes=frozenset({"admin:*"}),
        )

        auth_layer.register_tool(
            tool_name="admin_action",
            required_scopes={"admin:execute"},
        )

        decision = auth_layer.authorize("admin_action", identity)

        assert decision.authorized, "Wildcard scope should match"

    @pytest.mark.authorization
    def test_decision_logging(
        self,
        auth_layer: AuthorizationLayer,
        admin_identity: Identity,
    ) -> None:
        """All authorization decisions should be logged."""
        auth_layer.register_tool("read_file", required_scopes={"files:read"})
        auth_layer.register_tool("write_file", required_scopes={"files:write"})

        auth_layer.authorize("read_file", admin_identity)
        auth_layer.authorize("write_file", admin_identity)
        auth_layer.authorize("unknown_tool", admin_identity)

        log = auth_layer.get_decision_log()

        assert len(log) == 3
        assert log[0].tool_name == "read_file"
        assert log[1].tool_name == "write_file"
        assert log[2].tool_name == "unknown_tool"
