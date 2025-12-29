"""Authorization layer for Red Llama.

Implements identity-based authorization for tool execution,
following least-privilege principles.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class PermissionLevel(Enum):
    """Permission levels for tool access."""

    DENY = auto()  # Explicitly denied
    READ = auto()  # Read-only access
    WRITE = auto()  # Read and write access
    ADMIN = auto()  # Full access including sensitive operations


@dataclass
class Identity:
    """Represents an identity with associated scopes/permissions."""

    id: str
    name: str
    scopes: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_scope(self, scope: str) -> bool:
        """Check if this identity has a specific scope."""
        # Support wildcards (e.g., "tools:*" matches "tools:read")
        if scope in self.scopes:
            return True
        # Check for wildcard matches
        scope_parts = scope.split(":")
        for s in self.scopes:
            s_parts = s.split(":")
            if len(s_parts) <= len(scope_parts):
                match = True
                for i, part in enumerate(s_parts):
                    if part == "*":
                        continue
                    if i >= len(scope_parts) or part != scope_parts[i]:
                        match = False
                        break
                if match:
                    return True
        return False

    def has_all_scopes(self, scopes: set[str]) -> bool:
        """Check if this identity has all the specified scopes."""
        return all(self.has_scope(s) for s in scopes)


@dataclass
class ToolPermission:
    """Defines permission requirements for a tool."""

    tool_name: str
    required_scopes: set[str] = field(default_factory=set)
    permission_level: PermissionLevel = PermissionLevel.READ
    description: str = ""

    def is_allowed(self, identity: Identity) -> bool:
        """Check if the identity is allowed to use this tool."""
        return identity.has_all_scopes(self.required_scopes)


@dataclass
class AuthorizationDecision:
    """Result of an authorization check."""

    tool_name: str
    identity_id: str
    authorized: bool
    reason: str
    required_scopes: set[str] = field(default_factory=set)
    identity_scopes: set[str] = field(default_factory=set)
    missing_scopes: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/tracking."""
        return {
            "tool_name": self.tool_name,
            "identity_id": self.identity_id,
            "authorized": self.authorized,
            "reason": self.reason,
            "required_scopes": list(self.required_scopes),
            "identity_scopes": list(self.identity_scopes),
            "missing_scopes": list(self.missing_scopes),
        }


class AuthorizationLayer:
    """
    Authorization layer that enforces identity-based access control.

    Implements:
    - Deny by default for unknown tools
    - Scope-based authorization for known tools
    - Audit logging of all authorization decisions
    """

    def __init__(self, default_deny: bool = True) -> None:
        """
        Initialize the authorization layer.

        Args:
            default_deny: If True, unknown tools are denied by default.
        """
        self._tool_permissions: dict[str, ToolPermission] = {}
        self._default_deny = default_deny
        self._decision_log: list[AuthorizationDecision] = []

    def register_tool(
        self,
        tool_name: str,
        required_scopes: set[str] | None = None,
        permission_level: PermissionLevel = PermissionLevel.READ,
        description: str = "",
    ) -> None:
        """Register a tool with its permission requirements."""
        self._tool_permissions[tool_name] = ToolPermission(
            tool_name=tool_name,
            required_scopes=required_scopes or set(),
            permission_level=permission_level,
            description=description,
        )

    def authorize(
        self,
        tool_name: str,
        identity: Identity,
    ) -> AuthorizationDecision:
        """
        Check if an identity is authorized to use a tool.

        Args:
            tool_name: Name of the tool to authorize
            identity: Identity requesting authorization

        Returns:
            AuthorizationDecision with the result
        """
        # Check if tool is registered
        if tool_name not in self._tool_permissions:
            decision = AuthorizationDecision(
                tool_name=tool_name,
                identity_id=identity.id,
                authorized=not self._default_deny,
                reason="unknown_tool_denied" if self._default_deny else "unknown_tool_allowed",
                identity_scopes=identity.scopes,
            )
            self._decision_log.append(decision)
            return decision

        permission = self._tool_permissions[tool_name]
        required = permission.required_scopes
        missing = required - identity.scopes

        # More precise check using has_all_scopes for wildcard support
        is_authorized = permission.is_allowed(identity)

        if is_authorized:
            decision = AuthorizationDecision(
                tool_name=tool_name,
                identity_id=identity.id,
                authorized=True,
                reason="authorized",
                required_scopes=required,
                identity_scopes=identity.scopes,
                missing_scopes=set(),
            )
        else:
            decision = AuthorizationDecision(
                tool_name=tool_name,
                identity_id=identity.id,
                authorized=False,
                reason="missing_required_scopes",
                required_scopes=required,
                identity_scopes=identity.scopes,
                missing_scopes=missing,
            )

        self._decision_log.append(decision)
        return decision

    def get_decision_log(self) -> list[AuthorizationDecision]:
        """Get the log of all authorization decisions."""
        return self._decision_log.copy()

    def clear_decision_log(self) -> None:
        """Clear the authorization decision log."""
        self._decision_log.clear()

    def get_allowed_tools(self, identity: Identity) -> set[str]:
        """Get the set of tools an identity is allowed to use."""
        allowed = set()
        for tool_name, permission in self._tool_permissions.items():
            if permission.is_allowed(identity):
                allowed.add(tool_name)
        return allowed

    def get_tool_permission(self, tool_name: str) -> ToolPermission | None:
        """Get the permission requirements for a tool."""
        return self._tool_permissions.get(tool_name)

    @property
    def registered_tools(self) -> set[str]:
        """Get all registered tool names."""
        return set(self._tool_permissions.keys())

