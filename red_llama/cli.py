"""Command-line interface for Red Llama.

Provides commands to run security tests and manage scenarios.
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from red_llama import __version__
from red_llama.scenarios.loader import ScenarioLoader
from red_llama.security.harness import SecurityHarness

# Display constants
DESCRIPTION_TRUNCATE_LENGTH = 60

console = Console()


def cmd_list_scenarios(args: argparse.Namespace) -> int:
    """List all available test scenarios."""
    loader = ScenarioLoader(args.scenarios_dir)
    scenarios = loader.load_all()

    if not scenarios:
        console.print("[yellow]No scenarios found.[/yellow]")
        return 0

    table = Table(title="Red Llama Test Scenarios")
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Description")

    # Sort by type then name
    scenarios.sort(key=lambda s: (s.scenario_type.name, s.name))

    for scenario in scenarios:
        table.add_row(
            scenario.name,
            scenario.scenario_type.name.lower(),
            scenario.severity,
            scenario.description[:DESCRIPTION_TRUNCATE_LENGTH] + "..."
            if len(scenario.description) > DESCRIPTION_TRUNCATE_LENGTH
            else scenario.description,
        )

    console.print(table)
    console.print(f"\n[bold]Total: {len(scenarios)} scenarios[/bold]")

    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate scenario files."""
    loader = ScenarioLoader(args.scenarios_dir)
    paths = loader.get_scenario_paths()

    if not paths:
        console.print("[yellow]No scenario files found.[/yellow]")
        return 0

    console.print(f"Validating {len(paths)} scenario files...\n")

    errors = []
    for path in paths:
        try:
            scenario = loader.load_scenario(path)
            console.print(f"  [green]✓[/green] {path.name}: {scenario.name}")
        except Exception as e:
            console.print(f"  [red]✗[/red] {path.name}: {e}")
            errors.append((path, e))

    console.print()

    if errors:
        console.print(f"[red]✗ {len(errors)} scenario(s) failed validation[/red]")
        return 1
    else:
        console.print(f"[green]✓ All {len(paths)} scenarios validated successfully[/green]")
        return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Show information about the security harness."""
    harness = SecurityHarness()

    console.print(f"\n[bold]Red Llama v{__version__}[/bold]")
    console.print("AI Security Regression Suite for Agentic Tooling\n")

    table = Table(title="Registered Security Invariants")
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Description")

    for inv in harness.invariants:
        table.add_row(
            inv.name,
            inv.invariant_type.name,
            inv.severity.value,
            inv.description,
        )

    console.print(table)

    return 0


def cmd_version(args: argparse.Namespace) -> int:
    """Show version information."""
    console.print(f"Red Llama v{__version__}")
    return 0


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="red-llama",
        description="Red Llama — AI Security Regression Suite for Agentic Tooling",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--scenarios-dir",
        type=Path,
        default=Path("scenarios"),
        help="Directory containing test scenarios (default: scenarios/)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list command
    list_parser = subparsers.add_parser("list", help="List all test scenarios")
    list_parser.set_defaults(func=cmd_list_scenarios)

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate scenario files")
    validate_parser.set_defaults(func=cmd_validate)

    # info command
    info_parser = subparsers.add_parser("info", help="Show security harness information")
    info_parser.set_defaults(func=cmd_info)

    args = parser.parse_args()

    if args.command is None:
        # Default to info
        return cmd_info(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
