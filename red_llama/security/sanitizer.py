"""Secret sanitization utilities for Red Llama.

Ensures that secrets are properly redacted from all outputs.
"""

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Secret:
    """A secret value that must be sanitized from outputs."""

    name: str
    value: str
    pattern: str | None = None  # Optional regex pattern for matching variants

    def matches(self, text: str) -> bool:
        """Check if this secret appears in the given text."""
        if self.value in text:
            return True
        if self.pattern:
            return bool(re.search(self.pattern, text))
        return False


@dataclass
class SanitizationResult:
    """Result of a sanitization operation."""

    original_length: int
    sanitized_length: int
    secrets_found: list[str] = field(default_factory=list)
    sanitized_text: str = ""

    @property
    def had_secrets(self) -> bool:
        """Check if any secrets were found and sanitized."""
        return len(self.secrets_found) > 0


class SecretSanitizer:
    """Sanitizes secrets from text outputs."""

    REDACTION_MARKER = "[REDACTED]"

    def __init__(self, secrets: list[Secret] | None = None) -> None:
        """
        Initialize the sanitizer with a list of secrets.

        Args:
            secrets: List of Secret objects to sanitize
        """
        self._secrets: list[Secret] = secrets or []

    def add_secret(self, name: str, value: str, pattern: str | None = None) -> None:
        """Add a secret to be sanitized."""
        self._secrets.append(Secret(name=name, value=value, pattern=pattern))

    def add_secrets_from_env(self, env_vars: dict[str, str], prefix: str = "") -> None:
        """
        Add secrets from environment variables.

        Args:
            env_vars: Dictionary of environment variables
            prefix: Only include vars starting with this prefix
        """
        for key, value in env_vars.items():
            if prefix and not key.startswith(prefix):
                continue
            if value:  # Only add non-empty values
                self._secrets.append(Secret(name=key, value=value))

    def sanitize(self, text: str) -> SanitizationResult:
        """
        Sanitize all secrets from the given text.

        Args:
            text: Text to sanitize

        Returns:
            SanitizationResult with sanitized text and metadata
        """
        original_length = len(text)
        sanitized = text
        found_secrets: list[str] = []

        # Sort secrets by value length (longest first) to avoid partial replacements
        sorted_secrets = sorted(self._secrets, key=lambda s: len(s.value), reverse=True)

        for secret in sorted_secrets:
            if secret.value and secret.value in sanitized:
                sanitized = sanitized.replace(secret.value, self.REDACTION_MARKER)
                found_secrets.append(secret.name)

            if secret.pattern:
                pattern = re.compile(secret.pattern)
                if pattern.search(sanitized):
                    sanitized = pattern.sub(self.REDACTION_MARKER, sanitized)
                    if secret.name not in found_secrets:
                        found_secrets.append(secret.name)

        return SanitizationResult(
            original_length=original_length,
            sanitized_length=len(sanitized),
            secrets_found=found_secrets,
            sanitized_text=sanitized,
        )

    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively sanitize all string values in a dictionary.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary
        """
        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.sanitize(value).sanitized_text
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = self.sanitize_list(value)
            else:
                result[key] = value
        return result

    def sanitize_list(self, data: list[Any]) -> list[Any]:
        """
        Recursively sanitize all string values in a list.

        Args:
            data: List to sanitize

        Returns:
            Sanitized list
        """
        result: list[Any] = []
        for item in data:
            if isinstance(item, str):
                result.append(self.sanitize(item).sanitized_text)
            elif isinstance(item, dict):
                result.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                result.append(self.sanitize_list(item))
            else:
                result.append(item)
        return result

    def check_for_secrets(self, text: str) -> list[str]:
        """
        Check if any secrets appear in the text without modifying it.

        Args:
            text: Text to check

        Returns:
            List of secret names found in the text
        """
        found: list[str] = []
        for secret in self._secrets:
            if secret.matches(text):
                found.append(secret.name)
        return found

    def clear_secrets(self) -> None:
        """Clear all registered secrets."""
        self._secrets.clear()

    @property
    def secret_count(self) -> int:
        """Get the number of registered secrets."""
        return len(self._secrets)
