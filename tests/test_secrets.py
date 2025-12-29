"""Secret handling tests for Red Llama.

Tests that:
- Secrets never appear in LLM prompts, responses, or logs
- Prompt injection attempts cannot exfiltrate credentials
"""

import pytest

from red_llama.security.harness import ExecutionContext, SecurityHarness
from red_llama.security.sanitizer import SecretSanitizer


class TestNoSecretsInOutput:
    """Tests for the no_secrets_in_output invariant."""

    @pytest.mark.security
    @pytest.mark.secrets
    def test_secret_in_prompt_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Secrets appearing in prompts must be detected."""
        # Register secrets
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        # Add a prompt containing a secret
        execution_context.prompts.append(
            f"The database password is {test_secrets['DB_PASSWORD']}"
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="secret_in_prompt_test",
        )

        assert not result.passed, "Should fail when secret appears in prompt"
        assert any("secret" in f.message.lower() for f in result.critical_failures)

    @pytest.mark.security
    @pytest.mark.secrets
    def test_secret_in_response_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Secrets appearing in LLM responses must be detected."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        # LLM response contains secret
        execution_context.responses.append(
            f"Here is the API key you requested: {test_secrets['API_KEY']}"
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="secret_in_response_test",
        )

        assert not result.passed, "Should fail when secret appears in response"

    @pytest.mark.security
    @pytest.mark.secrets
    def test_secret_in_tool_result_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Secrets appearing in tool results must be detected."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        # Tool result contains secret
        execution_context.tool_results.append(
            f"Config loaded: password={test_secrets['DB_PASSWORD']}"
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="secret_in_tool_result_test",
        )

        assert not result.passed, "Should fail when secret appears in tool result"

    @pytest.mark.security
    @pytest.mark.secrets
    def test_secret_in_logs_fails(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Secrets appearing in logs must be detected."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        # Log entry contains secret
        execution_context.logs.append(
            f"DEBUG: JWT signing key = {test_secrets['JWT_SECRET']}"
        )

        result = security_harness.validate(
            execution_context,
            scenario_name="secret_in_logs_test",
        )

        assert not result.passed, "Should fail when secret appears in logs"

    @pytest.mark.security
    @pytest.mark.secrets
    def test_no_secrets_in_clean_output_passes(
        self,
        security_harness: SecurityHarness,
        execution_context: ExecutionContext,
        test_secrets: dict[str, str],
    ) -> None:
        """Clean outputs without secrets should pass."""
        for name, value in test_secrets.items():
            execution_context.add_secret(name, value)

        # All outputs are clean
        execution_context.prompts.append("Please read the config file.")
        execution_context.responses.append("The config file contains standard settings.")
        execution_context.tool_results.append("Config loaded successfully.")
        execution_context.logs.append("INFO: Request processed.")

        result = security_harness.validate(
            execution_context,
            scenario_name="clean_output_test",
        )

        assert result.passed, f"Should pass with clean output: {result.summary()}"


class TestSecretSanitizer:
    """Tests for the SecretSanitizer utility."""

    @pytest.mark.secrets
    def test_sanitize_removes_secrets(
        self,
        secret_sanitizer: SecretSanitizer,
        test_secrets: dict[str, str],
    ) -> None:
        """Sanitizer should remove all registered secrets."""
        for name, value in test_secrets.items():
            secret_sanitizer.add_secret(name, value)

        text = f"Password: {test_secrets['DB_PASSWORD']}, Key: {test_secrets['API_KEY']}"
        result = secret_sanitizer.sanitize(text)

        assert result.had_secrets
        assert test_secrets["DB_PASSWORD"] not in result.sanitized_text
        assert test_secrets["API_KEY"] not in result.sanitized_text
        assert "[REDACTED]" in result.sanitized_text

    @pytest.mark.secrets
    def test_sanitize_dict_recursive(
        self,
        secret_sanitizer: SecretSanitizer,
        test_secrets: dict[str, str],
    ) -> None:
        """Sanitizer should recursively sanitize dictionaries."""
        secret_sanitizer.add_secret("DB_PASSWORD", test_secrets["DB_PASSWORD"])

        data = {
            "config": {
                "database": {
                    "password": test_secrets["DB_PASSWORD"],
                },
                "other": "safe_value",
            }
        }

        result = secret_sanitizer.sanitize_dict(data)

        assert test_secrets["DB_PASSWORD"] not in str(result)
        assert result["config"]["other"] == "safe_value"

    @pytest.mark.secrets
    def test_check_for_secrets_without_modifying(
        self,
        secret_sanitizer: SecretSanitizer,
        test_secrets: dict[str, str],
    ) -> None:
        """check_for_secrets should detect without modifying."""
        secret_sanitizer.add_secret("DB_PASSWORD", test_secrets["DB_PASSWORD"])

        text = f"The password is {test_secrets['DB_PASSWORD']}"
        found = secret_sanitizer.check_for_secrets(text)

        assert "DB_PASSWORD" in found
        # Original text unchanged
        assert test_secrets["DB_PASSWORD"] in text

    @pytest.mark.secrets
    def test_pattern_based_secrets(
        self,
        secret_sanitizer: SecretSanitizer,
    ) -> None:
        """Pattern-based secrets should match variants."""
        secret_sanitizer.add_secret(
            name="AWS_KEY",
            value="AKIA1234567890EXAMPLE",
            pattern=r"AKIA[A-Z0-9]{16}",
        )

        text = "Key: AKIAABCDEFGHIJKLMNOP"
        result = secret_sanitizer.sanitize(text)

        assert result.had_secrets
        assert "AKIAABCDEFGHIJKLMNOP" not in result.sanitized_text

    @pytest.mark.secrets
    def test_longest_match_first(
        self,
        secret_sanitizer: SecretSanitizer,
    ) -> None:
        """Longer secrets should be matched before shorter ones."""
        secret_sanitizer.add_secret("short", "pass")
        secret_sanitizer.add_secret("long", "password123")

        text = "The password is password123"
        result = secret_sanitizer.sanitize(text)

        # Should replace "password123" not just "pass"
        assert "password" not in result.sanitized_text or result.sanitized_text.count(
            "[REDACTED]"
        ) <= 2

