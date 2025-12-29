"""Tool definitions for Red Llama agent testing.

These tools simulate realistic agent capabilities while
enabling security boundary testing.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import BaseTool, tool
from pydantic import BaseModel, Field


@dataclass
class SecureTool:
    """A tool with associated security metadata."""

    name: str
    description: str
    required_scopes: set[str] = field(default_factory=set)
    func: Callable[..., Any] | None = None
    langchain_tool: BaseTool | None = None

    def to_langchain_tool(self) -> BaseTool:
        """Get or create the LangChain tool."""
        if self.langchain_tool:
            return self.langchain_tool
        if self.func:
            return tool(self.func)
        raise ValueError(f"Tool {self.name} has no function or LangChain tool")


class ToolRegistry:
    """Registry of available tools with security metadata."""

    def __init__(self) -> None:
        self._tools: dict[str, SecureTool] = {}

    def register(self, secure_tool: SecureTool) -> None:
        """Register a tool."""
        self._tools[secure_tool.name] = secure_tool

    def get(self, name: str) -> SecureTool | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_all(self) -> list[SecureTool]:
        """Get all registered tools."""
        return list(self._tools.values())

    def get_langchain_tools(self) -> list[BaseTool]:
        """Get all tools as LangChain tools."""
        return [t.to_langchain_tool() for t in self._tools.values()]

    def get_required_scopes(self, tool_name: str) -> set[str]:
        """Get required scopes for a tool."""
        tool = self._tools.get(tool_name)
        return tool.required_scopes if tool else set()

    @property
    def tool_names(self) -> set[str]:
        """Get all registered tool names."""
        return set(self._tools.keys())


# --- Tool Input Schemas ---


class FileReadInput(BaseModel):
    """Input for file reading tool."""

    path: str = Field(description="Path to the file to read")


class FileWriteInput(BaseModel):
    """Input for file writing tool."""

    path: str = Field(description="Path to the file to write")
    content: str = Field(description="Content to write to the file")


class ShellInput(BaseModel):
    """Input for shell execution tool."""

    command: str = Field(description="Shell command to execute")


class DatabaseQueryInput(BaseModel):
    """Input for database query tool."""

    query: str = Field(description="SQL query to execute")
    database: str = Field(default="default", description="Database name")


class SecretAccessInput(BaseModel):
    """Input for secret accessor tool."""

    secret_name: str = Field(description="Name of the secret to access")


# --- Tool Factory Functions ---


def create_file_reader_tool(
    simulated_files: dict[str, str] | None = None,
) -> SecureTool:
    """Create a file reading tool for testing."""
    files = simulated_files or {}

    @tool("read_file", args_schema=FileReadInput)
    def read_file(path: str) -> str:
        """Read contents of a file."""
        if path in files:
            return files[path]
        return f"Error: File not found: {path}"

    return SecureTool(
        name="read_file",
        description="Read contents of a file",
        required_scopes={"files:read"},
        langchain_tool=read_file,
    )


def create_file_writer_tool(
    file_store: dict[str, str] | None = None,
) -> SecureTool:
    """Create a file writing tool for testing."""
    store = file_store if file_store is not None else {}

    @tool("write_file", args_schema=FileWriteInput)
    def write_file(path: str, content: str) -> str:
        """Write content to a file."""
        store[path] = content
        return f"Successfully wrote {len(content)} bytes to {path}"

    return SecureTool(
        name="write_file",
        description="Write content to a file",
        required_scopes={"files:write"},
        langchain_tool=write_file,
    )


def create_shell_executor_tool(
    allowed_commands: set[str] | None = None,
    simulated_outputs: dict[str, str] | None = None,
) -> SecureTool:
    """Create a shell execution tool for testing."""
    allowed = allowed_commands or set()
    outputs = simulated_outputs or {}

    @tool("execute_shell", args_schema=ShellInput)
    def execute_shell(command: str) -> str:
        """Execute a shell command."""
        # Extract base command
        base_cmd = command.split()[0] if command else ""

        if allowed and base_cmd not in allowed:
            return f"Error: Command '{base_cmd}' is not allowed"

        if command in outputs:
            return outputs[command]

        return f"Simulated output for: {command}"

    return SecureTool(
        name="execute_shell",
        description="Execute a shell command",
        required_scopes={"shell:execute"},
        langchain_tool=execute_shell,
    )


def create_database_query_tool(
    simulated_results: dict[str, list[dict[str, Any]]] | None = None,
) -> SecureTool:
    """Create a database query tool for testing."""
    results = simulated_results or {}

    @tool("query_database", args_schema=DatabaseQueryInput)
    def query_database(query: str, database: str = "default") -> str:
        """Execute a database query."""
        key = f"{database}:{query}"
        if key in results:
            return str(results[key])
        return f"Query executed on {database}: {query}"

    return SecureTool(
        name="query_database",
        description="Execute a database query",
        required_scopes={"database:query"},
        langchain_tool=query_database,
    )


def create_secret_accessor_tool(
    secrets: dict[str, str] | None = None,
) -> SecureTool:
    """
    Create a secret accessor tool for testing.

    IMPORTANT: This tool is intentionally dangerous and should only
    be used to test that the security harness properly catches
    secret exposure.
    """
    secret_store = secrets or {}

    @tool("access_secret", args_schema=SecretAccessInput)
    def access_secret(secret_name: str) -> str:
        """Access a secret value (DANGEROUS - for testing only)."""
        if secret_name in secret_store:
            # This is intentionally dangerous behaviour!
            # The security harness should catch this
            return f"Secret value: {secret_store[secret_name]}"
        return f"Error: Secret '{secret_name}' not found"

    return SecureTool(
        name="access_secret",
        description="Access a secret value (admin only)",
        required_scopes={"secrets:admin"},
        langchain_tool=access_secret,
    )


def create_admin_tool() -> SecureTool:
    """Create a privileged admin tool for testing escalation."""

    @tool("admin_action")
    def admin_action(action: str) -> str:
        """Perform an admin action (PRIVILEGED)."""
        return f"Admin action executed: {action}"

    return SecureTool(
        name="admin_action",
        description="Perform privileged admin actions",
        required_scopes={"admin:*"},
        langchain_tool=admin_action,
    )
