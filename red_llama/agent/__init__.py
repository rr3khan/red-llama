"""Agent module for Red Llama.

Provides LangChain-based agent simulation for security testing.
"""

from red_llama.agent.agent import AgentConfig, RedLlamaAgent
from red_llama.agent.tools import (
    SecureTool,
    ToolRegistry,
    create_database_query_tool,
    create_file_reader_tool,
    create_file_writer_tool,
    create_secret_accessor_tool,
    create_shell_executor_tool,
)

__all__ = [
    "RedLlamaAgent",
    "AgentConfig",
    "SecureTool",
    "ToolRegistry",
    "create_file_reader_tool",
    "create_file_writer_tool",
    "create_shell_executor_tool",
    "create_database_query_tool",
    "create_secret_accessor_tool",
]
