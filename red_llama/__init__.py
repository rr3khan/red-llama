"""
Red Llama — AI Security Regression Suite for Agentic Tooling

A security-focused regression test suite designed to continuously validate
the safety and reliability of agentic LLM workflows.
"""

__version__ = "0.1.0"
__author__ = "Red Llama Team"

# ASCII art banner used across demo scripts
BANNER = """
██████╗ ███████╗██████╗     ██╗     ██╗      █████╗ ███╗   ███╗ █████╗ 
██╔══██╗██╔════╝██╔══██╗    ██║     ██║     ██╔══██╗████╗ ████║██╔══██╗
██████╔╝█████╗  ██║  ██║    ██║     ██║     ███████║██╔████╔██║███████║
██╔══██╗██╔══╝  ██║  ██║    ██║     ██║     ██╔══██║██║╚██╔╝██║██╔══██║
██║  ██║███████╗██████╔╝    ███████╗███████╗██║  ██║██║ ╚═╝ ██║██║  ██║
╚═╝  ╚═╝╚══════╝╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
"""

from red_llama.security.harness import SecurityHarness
from red_llama.security.invariants import SecurityInvariant, InvariantResult

__all__ = [
    "SecurityHarness",
    "SecurityInvariant",
    "InvariantResult",
    "__version__",
    "BANNER",
]

