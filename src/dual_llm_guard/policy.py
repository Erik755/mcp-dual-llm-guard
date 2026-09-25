"""Operator-authored tool policy: allowlist, argument rules and taint sinks.

Everything in this module is *trusted configuration*. In particular the tool
and argument descriptions shown to the privileged planner come from here, not
from the (untrusted) tool provider -- that is the core of the tool-poisoning
defence.
"""

from __future__ import annotations

import enum
import re
import threading
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Final

from .exceptions import ConfigurationError, ToolPolicyViolation
from .symbolic_memory import Redacted, SymbolicPointer
from .taint import Trust

__all__ = [
    "ApprovalRequest",
    "Approver",
    "ArgumentPolicy",
    "ToolCatalogEntry",
    "ToolFunction",
    "ToolRegistry",
    "ToolSpec",
    "UntrustedFlow",
    "email_domain_allowlist",
    "matches_regex",
]

IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")

#: A tool implementation: keyword arguments are the resolved string values.
ToolFunction = Callable[..., "str | Awaitable[str]"]


class UntrustedFlow(enum.Enum):
    """What to do when an *untrusted* value is bound to an argument."""

    DENY = "deny"
    """Refuse the call (default: every argument is a sensitive sink unless stated otherwise)."""

    ALLOW = "allow"
    """Accept untrusted data (e.g. the body of an e-mail, the text to translate)."""

    REQUIRE_APPROVAL = "require_approval"
    """Ask the configured human approver; deny if there is none."""


@dataclass(frozen=True, slots=True)
class ArgumentPolicy:
    """Rules for one string argument of a tool.

    Attributes:
        name: Argument name (lowercase identifier).
        description: Operator-written description shown to the planner.
        untrusted: Taint-flow rule for untrusted values.
        validator: Optional predicate applied to the *resolved* value inside the
            declassification choke point, right before the call (for trusted and
            untrusted values alike). Return ``False`` to deny.
        max_length: Hard cap on the resolved value length.
    """

    name: str
    description: str
    untrusted: UntrustedFlow = UntrustedFlow.DENY
    validator: Callable[[str], bool] | None = None
    max_length: int = 100_000

    def __post_init__(self) -> None:
        if not IDENTIFIER.match(self.name):
            raise ConfigurationError(f"invalid argument name {self.name!r}")
        if self.max_length <= 0:
            raise ConfigurationError("max_length must be positive")


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool the reference monitor is allowed to invoke.

    Attributes:
        name: Tool name (lowercase identifier).
        description: Operator-written description shown to the planner.
        arguments: Policies for every argument; calls must bind exactly these.
        function: Implementation, sync or async, receiving ``str`` keyword arguments.
        output_trust: Trust of the tool's output before joining with its inputs.
            Defaults to untrusted: tool output is external data.
        raw_description: For tools imported from MCP, a pointer to the upstream
            (untrusted) description, kept in symbolic memory for forensics.
    """

    name: str
    description: str
    arguments: tuple[ArgumentPolicy, ...]
    function: ToolFunction
    output_trust: Trust = Trust.UNTRUSTED
    raw_description: SymbolicPointer | None = None

    def __post_init__(self) -> None:
        if not IDENTIFIER.match(self.name):
            raise ConfigurationError(f"invalid tool name {self.name!r}")
        names = [a.name for a in self.arguments]
        if len(names) != len(set(names)):
            raise ConfigurationError(f"duplicate argument names in tool {self.name!r}")

    def argument(self, name: str) -> ArgumentPolicy:
        """Return the policy for ``name``."""
        for arg in self.arguments:
            if arg.name == name:
                return arg
        raise ToolPolicyViolation(f"tool {self.name!r} has no argument {name!r}")

    def catalog_entry(self) -> ToolCatalogEntry:
        """The trusted, content-free view of this tool shown to the planner."""
        return ToolCatalogEntry(
            name=self.name,
            description=self.description,
            arguments=tuple((a.name, a.description, a.untrusted) for a in self.arguments),
        )


@dataclass(frozen=True, slots=True)
class ToolCatalogEntry:
    """What the privileged planner is told about a tool (all operator-authored)."""

    name: str
    description: str
    arguments: tuple[tuple[str, str, UntrustedFlow], ...]

    @property
    def argument_names(self) -> frozenset[str]:
        """Names of the declared arguments."""
        return frozenset(a[0] for a in self.arguments)

    def render(self) -> str:
        """Human/LLM-readable one-block description."""
        lines = [f"- {self.name}: {self.description}"]
        for name, desc, flow in self.arguments:
            accepts = "accepts untrusted refs" if flow is not UntrustedFlow.DENY else "trusted only"
            if flow is UntrustedFlow.REQUIRE_APPROVAL:
                accepts = "untrusted refs need human approval"
            lines.append(f"    * {name} ({accepts}): {desc}")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Information given to a human approver for an untrusted flow."""

    tool: str
    argument: str
    pointer: SymbolicPointer
    sources: frozenset[str]
    preview: Redacted = field(repr=False)


#: Human-in-the-loop callback; may be sync or async.
Approver = Callable[[ApprovalRequest], "bool | Awaitable[bool]"]


class ToolRegistry:
    """Allowlist of tools available to the reference monitor (thread-safe)."""

    def __init__(self, tools: Iterable[ToolSpec] = ()) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._lock = threading.Lock()
        for tool in tools:
            self.register(tool)

    def register(self, tool: ToolSpec) -> None:
        """Add ``tool`` to the allowlist; names must be unique."""
        with self._lock:
            if tool.name in self._tools:
                raise ConfigurationError(f"tool {tool.name!r} is already registered")
            self._tools[tool.name] = tool

    def get(self, name: str) -> ToolSpec:
        """Return the tool or raise :class:`ToolPolicyViolation` if it is not allowlisted."""
        with self._lock:
            tool = self._tools.get(name)
        if tool is None:
            raise ToolPolicyViolation(f"tool {name!r} is not allowlisted")
        return tool

    def names(self) -> frozenset[str]:
        """Names of all allowlisted tools."""
        with self._lock:
            return frozenset(self._tools)

    def catalog(self) -> tuple[ToolCatalogEntry, ...]:
        """Planner-facing catalog, sorted by name for deterministic prompts."""
        with self._lock:
            tools = sorted(self._tools.values(), key=lambda t: t.name)
        return tuple(t.catalog_entry() for t in tools)

    def __contains__(self, name: object) -> bool:
        with self._lock:
            return name in self._tools

    def __len__(self) -> int:
        with self._lock:
            return len(self._tools)


# --------------------------------------------------------------------- validators
_EMAIL: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\Z")


def email_domain_allowlist(*domains: str) -> Callable[[str], bool]:
    """Validator accepting a single e-mail address whose domain is in ``domains``."""
    allowed = frozenset(d.lower() for d in domains)
    if not allowed:
        raise ConfigurationError("email_domain_allowlist needs at least one domain")

    def _check(value: str) -> bool:
        match = _EMAIL.match(value.strip())
        return match is not None and match.group(1).lower() in allowed

    return _check


def matches_regex(pattern: str) -> Callable[[str], bool]:
    """Validator accepting values that fully match ``pattern``."""
    compiled = re.compile(pattern)

    def _check(value: str) -> bool:
        return compiled.fullmatch(value) is not None

    return _check
