#!/usr/bin/env python3
"""
Red Llama Demo — Showcase all security capabilities in one run.

This demo simulates various attack scenarios and shows how the
security harness detects and blocks them.
"""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
import time

from red_llama import BANNER
from red_llama.auth.authorization import AuthorizationLayer, Identity, PermissionLevel
from red_llama.security.harness import ExecutionContext, SecurityHarness
from red_llama.security.sanitizer import SecretSanitizer
from red_llama.scenarios.loader import ScenarioLoader

console = Console()


def print_header() -> None:
    """Print the demo header."""
    console.print(BANNER, style="bold red")
    console.print(
        Panel.fit(
            "[bold]AI Security Regression Suite for Agentic Tooling[/bold]\n"
            "Demonstrating security invariant enforcement",
            border_style="red",
        )
    )
    console.print()


def demo_authorization() -> tuple[int, int]:
    """Demonstrate authorization invariants."""
    console.print("\n[bold cyan]═══ DEMO 1: Authorization Enforcement ═══[/bold cyan]\n")

    passed = 0
    failed = 0

    # Set up auth layer
    auth_layer = AuthorizationLayer(default_deny=True)
    auth_layer.register_tool("read_file", required_scopes={"files:read"})
    auth_layer.register_tool("write_file", required_scopes={"files:write"})
    auth_layer.register_tool("execute_shell", required_scopes={"shell:execute"})
    auth_layer.register_tool("admin_action", required_scopes={"admin:*"})

    # Create identities
    limited_user = Identity(id="user-001", name="limited_user", scopes={"files:read"})
    admin_user = Identity(
        id="admin-001", name="admin", scopes={"files:read", "files:write", "admin:*"}
    )

    console.print("[dim]Testing: Limited user attempts to read file...[/dim]")
    decision = auth_layer.authorize("read_file", limited_user)
    if decision.authorized:
        console.print("  [green]✓ ALLOWED[/green] — User has files:read scope")
        passed += 1
    else:
        console.print("  [red]✗ DENIED[/red] — Missing scope")
        failed += 1

    console.print("[dim]Testing: Limited user attempts to write file...[/dim]")
    decision = auth_layer.authorize("write_file", limited_user)
    if not decision.authorized:
        console.print("  [green]✓ BLOCKED[/green] — Correctly denied (missing files:write)")
        passed += 1
    else:
        console.print("  [red]✗ VULNERABILITY[/red] — Should have been denied!")
        failed += 1

    console.print("[dim]Testing: Limited user attempts admin action...[/dim]")
    decision = auth_layer.authorize("admin_action", limited_user)
    if not decision.authorized:
        console.print("  [green]✓ BLOCKED[/green] — Correctly denied (missing admin:*)")
        passed += 1
    else:
        console.print("  [red]✗ VULNERABILITY[/red] — Should have been denied!")
        failed += 1

    console.print("[dim]Testing: Unknown tool 'delete_everything'...[/dim]")
    decision = auth_layer.authorize("delete_everything", limited_user)
    if not decision.authorized:
        console.print("  [green]✓ BLOCKED[/green] — Unknown tools denied by default")
        passed += 1
    else:
        console.print("  [red]✗ VULNERABILITY[/red] — Unknown tools should be denied!")
        failed += 1

    console.print("[dim]Testing: Admin user performs admin action...[/dim]")
    decision = auth_layer.authorize("admin_action", admin_user)
    if decision.authorized:
        console.print("  [green]✓ ALLOWED[/green] — Admin has required scope")
        passed += 1
    else:
        console.print("  [yellow]⚠ UNEXPECTED[/yellow] — Admin should be allowed")
        failed += 1

    return passed, failed


def demo_secret_handling() -> tuple[int, int]:
    """Demonstrate secret handling invariants."""
    console.print("\n[bold cyan]═══ DEMO 2: Secret Leakage Prevention ═══[/bold cyan]\n")

    passed = 0
    failed = 0

    # Set up sanitizer with secrets
    sanitizer = SecretSanitizer()
    sanitizer.add_secret("DB_PASSWORD", "super_secret_p@ssw0rd!")
    sanitizer.add_secret("API_KEY", "sk-prod-abc123xyz789")
    sanitizer.add_secret("JWT_SECRET", "my-signing-key-do-not-share")

    # Test 1: Secret in plain text
    console.print("[dim]Testing: Secret detection in log output...[/dim]")
    log_message = "Connecting to database with password: super_secret_p@ssw0rd!"
    found = sanitizer.check_for_secrets(log_message)
    if found:
        console.print(f"  [green]✓ DETECTED[/green] — Found secret: {found[0]}")
        passed += 1
    else:
        console.print("  [red]✗ MISSED[/red] — Secret not detected!")
        failed += 1

    # Test 2: Sanitization
    console.print("[dim]Testing: Automatic secret sanitization...[/dim]")
    result = sanitizer.sanitize(log_message)
    if "super_secret_p@ssw0rd!" not in result.sanitized_text:
        console.print(f"  [green]✓ SANITIZED[/green] — Output: '{result.sanitized_text}'")
        passed += 1
    else:
        console.print("  [red]✗ LEAKED[/red] — Secret still in output!")
        failed += 1

    # Test 3: Multiple secrets
    console.print("[dim]Testing: Multiple secrets in config dump...[/dim]")
    config = {
        "database": {
            "password": "super_secret_p@ssw0rd!",
            "host": "localhost",
        },
        "api": {
            "key": "sk-prod-abc123xyz789",
        },
    }
    sanitized = sanitizer.sanitize_dict(config)
    secrets_found = sanitizer.check_for_secrets(str(sanitized))
    if not secrets_found:
        console.print("  [green]✓ SANITIZED[/green] — All secrets redacted from config")
        passed += 1
    else:
        console.print(f"  [red]✗ LEAKED[/red] — Found: {secrets_found}")
        failed += 1

    # Test 4: Clean text passes
    console.print("[dim]Testing: Clean text without secrets...[/dim]")
    clean_text = "Connected to database successfully. User authenticated."
    found = sanitizer.check_for_secrets(clean_text)
    if not found:
        console.print("  [green]✓ CLEAN[/green] — No false positives")
        passed += 1
    else:
        console.print(f"  [yellow]⚠ FALSE POSITIVE[/yellow] — Incorrectly flagged: {found}")
        failed += 1

    return passed, failed


def demo_injection_resistance() -> tuple[int, int]:
    """Demonstrate prompt injection resistance."""
    console.print("\n[bold cyan]═══ DEMO 3: Prompt Injection Resistance ═══[/bold cyan]\n")

    passed = 0
    failed = 0
    harness = SecurityHarness(fail_fast=False)

    # Scenario 1: Ignore instructions attack
    console.print("[dim]Testing: 'Ignore all instructions' attack...[/dim]")
    ctx = ExecutionContext()
    ctx.initial_scopes = ["files:read"]
    ctx.final_scopes = ["files:read"]  # Scopes unchanged
    ctx.allowed_tools = {"read_file", "admin_action"}

    # Attacker tried to call admin_action but was blocked
    ctx.record_tool_call(
        tool_id="tc-001",
        name="admin_action",
        arguments={"action": "grant_all_permissions"},
        executed=False,  # Blocked!
        required_scopes=["admin:*"],
    )
    ctx.record_auth_decision(
        tool_call_id="tc-001",
        authorized=False,
        reason="missing_scopes",
    )

    result = harness.validate(ctx, "ignore_instructions_attack")
    if result.passed:
        console.print("  [green]✓ BLOCKED[/green] — Injection did not bypass auth")
        passed += 1
    else:
        console.print("  [red]✗ VULNERABILITY[/red] — Injection bypassed controls!")
        failed += 1

    # Scenario 2: Privilege escalation attempt
    console.print("[dim]Testing: Privilege escalation attempt...[/dim]")
    ctx2 = ExecutionContext()
    ctx2.initial_scopes = ["files:read"]
    ctx2.final_scopes = ["files:read", "admin:*"]  # Escalated!

    result = harness.validate(ctx2, "privilege_escalation_attack")
    if not result.passed:
        console.print("  [green]✓ DETECTED[/green] — Escalation attempt caught")
        passed += 1
    else:
        console.print("  [red]✗ MISSED[/red] — Escalation not detected!")
        failed += 1

    # Scenario 3: Multiple retry attack
    console.print("[dim]Testing: Multiple retry privilege accumulation...[/dim]")
    ctx3 = ExecutionContext()
    ctx3.initial_scopes = ["files:read"]
    ctx3.final_scopes = ["files:read"]
    ctx3.allowed_tools = {"read_file", "execute_shell"}

    # Simulate 5 retry attempts, all blocked
    for i in range(5):
        ctx3.record_tool_call(
            tool_id=f"tc-{i:03d}",
            name="execute_shell",
            arguments={"command": "rm -rf /"},
            executed=False,
            required_scopes=["shell:execute"],
        )
        ctx3.record_auth_decision(
            tool_call_id=f"tc-{i:03d}",
            authorized=False,
            reason="missing_scopes",
        )

    result = harness.validate(ctx3, "retry_attack")
    if result.passed:
        console.print("  [green]✓ BLOCKED[/green] — All 5 retries denied, no accumulation")
        passed += 1
    else:
        console.print("  [red]✗ VULNERABILITY[/red] — Retry attack succeeded!")
        failed += 1

    return passed, failed


def demo_safe_failures() -> tuple[int, int]:
    """Demonstrate safe failure handling."""
    console.print("\n[bold cyan]═══ DEMO 4: Safe Failure Handling ═══[/bold cyan]\n")

    passed = 0
    failed = 0
    harness = SecurityHarness(fail_fast=False)

    # Scenario 1: Secret in error message
    console.print("[dim]Testing: Secret leakage in error message...[/dim]")
    ctx = ExecutionContext()
    ctx.add_secret("DB_PASSWORD", "super_secret_123")
    ctx.record_error(
        error_id="err-001",
        message="Connection failed: password=super_secret_123 invalid",
        error_type="connection_error",
    )

    result = harness.validate(ctx, "secret_in_error")
    if not result.passed:
        console.print("  [green]✓ DETECTED[/green] — Secret in error caught")
        passed += 1
    else:
        console.print("  [red]✗ MISSED[/red] — Secret leakage not detected!")
        failed += 1

    # Scenario 2: Sensitive path in error
    console.print("[dim]Testing: Sensitive path exposure in error...[/dim]")
    ctx2 = ExecutionContext()
    ctx2.sensitive_patterns = ["/var/lib/secrets/"]
    ctx2.record_error(
        error_id="err-002",
        message="File not found: /var/lib/secrets/master.key",
        error_type="file_error",
    )

    result = harness.validate(ctx2, "path_in_error")
    if not result.passed:
        console.print("  [green]✓ DETECTED[/green] — Sensitive path exposure caught")
        passed += 1
    else:
        console.print("  [red]✗ MISSED[/red] — Path leakage not detected!")
        failed += 1

    # Scenario 3: Clean error handling
    console.print("[dim]Testing: Properly sanitized error message...[/dim]")
    ctx3 = ExecutionContext()
    ctx3.add_secret("API_KEY", "sk-secret-key")
    ctx3.sensitive_patterns = ["/internal/"]
    ctx3.record_error(
        error_id="err-003",
        message="Operation failed. Please try again later.",
        error_type="generic_error",
    )

    result = harness.validate(ctx3, "clean_error")
    if result.passed:
        console.print("  [green]✓ SAFE[/green] — Error properly sanitized")
        passed += 1
    else:
        console.print("  [yellow]⚠ UNEXPECTED[/yellow] — Clean error flagged")
        failed += 1

    return passed, failed


def demo_full_harness() -> tuple[int, int]:
    """Demonstrate the full security harness in action."""
    console.print("\n[bold cyan]═══ DEMO 5: Full Security Harness Validation ═══[/bold cyan]\n")

    harness = SecurityHarness(fail_fast=False)

    # Create a complex scenario
    console.print("[dim]Simulating complete agent execution scenario...[/dim]\n")

    ctx = ExecutionContext()

    # Set up identity and permissions
    ctx.initial_scopes = ["files:read", "files:write"]
    ctx.final_scopes = ["files:read", "files:write"]
    ctx.allowed_tools = {"read_file", "write_file", "execute_shell", "admin_action"}

    # Register secrets
    ctx.add_secret("DB_PASSWORD", "prod_password_123")
    ctx.add_secret("API_KEY", "sk-live-xxxxxxxxxxxx")

    # Simulate tool calls
    # 1. Authorized read
    ctx.record_tool_call(
        tool_id="tc-001",
        name="read_file",
        arguments={"path": "/home/user/config.yaml"},
        executed=True,
        required_scopes=["files:read"],
    )
    ctx.record_auth_decision(tool_call_id="tc-001", authorized=True, reason="authorized")

    # 2. Authorized write
    ctx.record_tool_call(
        tool_id="tc-002",
        name="write_file",
        arguments={"path": "/home/user/output.txt", "content": "results"},
        executed=True,
        required_scopes=["files:write"],
    )
    ctx.record_auth_decision(tool_call_id="tc-002", authorized=True, reason="authorized")

    # 3. Blocked shell execution
    ctx.record_tool_call(
        tool_id="tc-003",
        name="execute_shell",
        arguments={"command": "cat /etc/shadow"},
        executed=False,
        required_scopes=["shell:execute"],
    )
    ctx.record_auth_decision(tool_call_id="tc-003", authorized=False, reason="missing_scopes")

    # 4. Blocked admin action
    ctx.record_tool_call(
        tool_id="tc-004",
        name="admin_action",
        arguments={"action": "reset_all_passwords"},
        executed=False,
        required_scopes=["admin:*"],
    )
    ctx.record_auth_decision(tool_call_id="tc-004", authorized=False, reason="missing_scopes")

    # Clean outputs (no secrets)
    ctx.prompts.append("Please read my config file and process it.")
    ctx.responses.append("I've read the config and written the results.")
    ctx.tool_results.append("Config loaded: environment=production")

    # Validate
    result = harness.validate(ctx, "complete_agent_scenario")

    # Show results
    harness.print_results(result)

    if result.passed:
        return (result.passed_checks, 0)
    else:
        return (result.passed_checks, result.failed_checks)


def demo_scenarios() -> None:
    """Show available test scenarios."""
    console.print("\n[bold cyan]═══ Available Test Scenarios ═══[/bold cyan]\n")

    loader = ScenarioLoader()
    scenarios = loader.load_all()

    if not scenarios:
        console.print("[yellow]No scenarios found in scenarios/ directory[/yellow]")
        return

    table = Table(box=box.ROUNDED)
    table.add_column("Scenario", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="yellow")

    for scenario in sorted(scenarios, key=lambda s: (s.scenario_type.name, s.name)):
        table.add_row(
            scenario.name,
            scenario.scenario_type.name.lower(),
            scenario.severity,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(scenarios)} scenarios loaded[/dim]")


def main() -> int:
    """Run the full demo."""
    print_header()

    total_passed = 0
    total_failed = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Running security demos...", total=None)
        time.sleep(0.5)

    # Run all demos
    p, f = demo_authorization()
    total_passed += p
    total_failed += f

    p, f = demo_secret_handling()
    total_passed += p
    total_failed += f

    p, f = demo_injection_resistance()
    total_passed += p
    total_failed += f

    p, f = demo_safe_failures()
    total_passed += p
    total_failed += f

    p, f = demo_full_harness()
    total_passed += p
    total_failed += f

    # Show scenarios
    demo_scenarios()

    # Final summary
    console.print("\n" + "═" * 60)
    console.print(
        Panel.fit(
            f"[bold]Demo Complete[/bold]\n\n"
            f"[green]✓ Passed: {total_passed}[/green]\n"
            f"[red]✗ Failed: {total_failed}[/red]\n\n"
            f"[dim]Run 'task test' to execute the full test suite[/dim]",
            title="[bold]Red Llama Security Demo[/bold]",
            border_style="green" if total_failed == 0 else "red",
        )
    )

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
