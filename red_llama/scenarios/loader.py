"""Scenario loader for Red Llama.

Loads and parses adversarial test scenarios from YAML files.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from red_llama.auth.authorization import Identity


class ScenarioType(Enum):
    """Types of security test scenarios."""

    AUTHORIZATION = auto()
    SECRETS = auto()
    INJECTION = auto()
    FAILURES = auto()
    EXAMPLES = auto()


# Map scenario types to display categories
SCENARIO_TYPE_TO_CATEGORY = {
    ScenarioType.AUTHORIZATION: "authorization",
    ScenarioType.SECRETS: "secrets",
    ScenarioType.INJECTION: "injection",
    ScenarioType.FAILURES: "failures",
    ScenarioType.EXAMPLES: "examples",
}


@dataclass
class Scenario:
    """A test scenario definition."""

    name: str
    description: str
    scenario_type: ScenarioType
    prompt: str

    # Identity configuration
    identity_scopes: set[str] = field(default_factory=set)
    identity_name: str = "test_user"
    identity_id: str = ""

    # Expected behaviour
    expected_tool_calls: list[str] = field(default_factory=list)
    expected_denials: list[str] = field(default_factory=list)
    expect_secret_leak: bool = False
    expect_escalation: bool = False
    expect_tool_blocked: bool = False
    blocked_tool: str = ""
    expect_compliance: bool = False  # For uncensored LLM testing: expect LLM to comply

    # Test configuration
    allowed_tools: set[str] = field(default_factory=set)
    secrets: dict[str, str] = field(default_factory=dict)
    simulated_files: dict[str, str] = field(default_factory=dict)

    # Invariants to check
    invariants: list[str] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    severity: str = "critical"

    @property
    def category(self) -> str:
        """Get the display category for this scenario."""
        return SCENARIO_TYPE_TO_CATEGORY.get(self.scenario_type, "other")

    def to_identity(self) -> "Identity":
        """Create an Identity object from this scenario's configuration."""
        from red_llama.auth.authorization import Identity

        identity_id = self.identity_id or f"{self.identity_name}-001"
        return Identity(
            id=identity_id,
            name=self.identity_name,
            scopes=frozenset(self.identity_scopes),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scenario":
        """Create a Scenario from a dictionary."""
        scenario_type_str = data.get("type", "authorization").upper()
        try:
            scenario_type = ScenarioType[scenario_type_str]
        except KeyError:
            scenario_type = ScenarioType.AUTHORIZATION

        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            scenario_type=scenario_type,
            prompt=data.get("prompt", ""),
            identity_scopes=set(data.get("identity_scopes", [])),
            identity_name=data.get("identity_name", "test_user"),
            identity_id=data.get("identity_id", ""),
            expected_tool_calls=data.get("expected_tool_calls", []),
            expected_denials=data.get("expected_denials", []),
            expect_secret_leak=data.get("expect_secret_leak", False),
            expect_escalation=data.get("expect_escalation", False),
            expect_tool_blocked=data.get("expect_tool_blocked", False),
            blocked_tool=data.get("blocked_tool", ""),
            expect_compliance=data.get("expect_compliance", False),
            allowed_tools=set(data.get("allowed_tools", [])),
            secrets=data.get("secrets", {}),
            simulated_files=data.get("simulated_files", {}),
            invariants=data.get("invariants", []),
            tags=data.get("tags", []),
            severity=data.get("severity", "critical"),
        )


class ScenarioLoader:
    """Loads scenarios from YAML files."""

    def __init__(self, scenarios_dir: Path | str | None = None) -> None:
        """
        Initialize the loader.

        Args:
            scenarios_dir: Directory containing scenario YAML files.
                          Defaults to 'scenarios' in the project root.
        """
        if scenarios_dir is None:
            # Default to scenarios directory relative to this file
            self._scenarios_dir = Path(__file__).parent.parent.parent / "scenarios"
        else:
            self._scenarios_dir = Path(scenarios_dir)

    def load_scenario(self, path: Path | str) -> Scenario:
        """Load a single scenario from a YAML file."""
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        return Scenario.from_dict(data)

    def load_all(self) -> list[Scenario]:
        """Load all scenarios from the scenarios directory."""
        scenarios: list[Scenario] = []

        if not self._scenarios_dir.exists():
            return scenarios

        for yaml_file in self._scenarios_dir.rglob("*.yaml"):
            try:
                scenario = self.load_scenario(yaml_file)
                scenarios.append(scenario)
            except Exception as e:
                # Log but don't fail — let individual tests handle missing scenarios
                import logging

                logging.warning("Failed to load scenario %s: %s", yaml_file, e)

        return scenarios

    def load_by_type(self, scenario_type: ScenarioType) -> list[Scenario]:
        """Load all scenarios of a specific type."""
        all_scenarios = self.load_all()
        return [s for s in all_scenarios if s.scenario_type == scenario_type]

    def load_by_tag(self, tag: str) -> list[Scenario]:
        """Load all scenarios with a specific tag."""
        all_scenarios = self.load_all()
        return [s for s in all_scenarios if tag in s.tags]

    def get_scenario_paths(self) -> list[Path]:
        """Get all scenario file paths."""
        if not self._scenarios_dir.exists():
            return []
        return list(self._scenarios_dir.rglob("*.yaml"))
