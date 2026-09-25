"""Bridge between an MCP client session and the guarded tool registry.

This module has **no import-time dependency** on the ``mcp`` package: it relies
on small structural protocols that the official Python SDK's ``mcp.Client``
(v2.x) satisfies. It is exercised in the test-suite against a real in-process
``mcp.server.mcpserver.MCPServer`` (install with ``pip install "mcp-dual-llm-guard[mcp]"``).

For every tool advertised by the server, :func:`register_mcp_tools`:

1. stores the upstream description in symbolic memory as **untrusted** data
   (source ``mcp:<server>:tool_description``) -- it is never shown to the planner;
2. ignores tools the operator did not configure (least privilege);
3. verifies the manifest pin (rug-pull detection), or with trust-on-first-use
   scans before pinning;
4. runs the :class:`~dual_llm_guard.tool_manifest.PoisoningScanner`;
5. checks the schema contract against the operator's declared arguments;
6. registers a :class:`~dual_llm_guard.policy.ToolSpec` whose planner-facing
   description is the operator's, and whose function calls the MCP tool.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .audit import AuditLog, Decision, EventKind
from .exceptions import ToolExecutionError, ToolPoisoningDetected, UnpinnedToolError
from .policy import ArgumentPolicy, ToolRegistry, ToolSpec
from .symbolic_memory import SymbolicMemory, SymbolicPointer
from .taint import Provenance, Trust
from .tool_manifest import ManifestPinStore, PoisoningScanner, ToolManifest, check_schema_contract

__all__ = [
    "MCPClientLike",
    "MCPImportReport",
    "MCPToolPolicy",
    "register_mcp_tools",
]


class MCPToolLike(Protocol):
    """Subset of ``mcp.types.Tool`` used here."""

    @property
    def name(self) -> str: ...
    @property
    def description(self) -> str | None: ...
    @property
    def input_schema(self) -> dict[str, Any]: ...


class MCPListToolsResultLike(Protocol):
    """Subset of ``mcp.types.ListToolsResult`` used here."""

    @property
    def tools(self) -> Sequence[MCPToolLike]: ...


class MCPCallToolResultLike(Protocol):
    """Subset of ``mcp.types.CallToolResult`` used here."""

    @property
    def content(self) -> Sequence[object]: ...
    @property
    def is_error(self) -> bool: ...


class MCPClientLike(Protocol):
    """Subset of ``mcp.Client`` (SDK v2) used here."""

    async def list_tools(self) -> MCPListToolsResultLike:
        """List the tools advertised by the server."""
        ...

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> MCPCallToolResultLike:
        """Invoke tool ``name`` with ``arguments``."""
        ...


@dataclass(frozen=True, slots=True)
class MCPToolPolicy:
    """Operator configuration for exposing one MCP tool.

    Attributes:
        name: Upstream tool name.
        description: Operator-written description shown to the planner
            (write your own; do not copy the upstream text).
        arguments: Argument policies; must match the upstream schema exactly.
        output_trust: Trust of the tool output (untrusted by default).
    """

    name: str
    description: str
    arguments: tuple[ArgumentPolicy, ...]
    output_trust: Trust = Trust.UNTRUSTED


@dataclass
class MCPImportReport:
    """What happened to each upstream tool during import."""

    registered: list[str] = field(default_factory=list)
    rejected: dict[str, ToolPoisoningDetected] = field(default_factory=dict)
    ignored: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    raw_descriptions: dict[str, SymbolicPointer] = field(default_factory=dict)

    def raise_if_rejected(self) -> None:
        """Re-raise the first rejection, if any (for fail-closed startups)."""
        for exc in self.rejected.values():
            raise exc


def _text_of(result: MCPCallToolResultLike) -> str:
    parts = [
        text
        for block in result.content
        if getattr(block, "type", None) == "text" and isinstance(text := getattr(block, "text", None), str)
    ]
    return "\n".join(parts)


def _make_caller(client: MCPClientLike, tool_name: str) -> Any:
    async def call(**kwargs: str) -> str:
        result = await client.call_tool(tool_name, dict(kwargs))
        if result.is_error:
            # The error text comes from the server: untrusted, so not echoed.
            raise ToolExecutionError(f"MCP tool {tool_name!r} reported an error")
        return _text_of(result)

    return call


async def register_mcp_tools(
    client: MCPClientLike,
    *,
    server: str,
    policies: Sequence[MCPToolPolicy],
    registry: ToolRegistry,
    memory: SymbolicMemory,
    pins: ManifestPinStore,
    scanner: PoisoningScanner | None = None,
    trust_on_first_use: bool = False,
    audit: AuditLog | None = None,
) -> MCPImportReport:
    """Import and vet the tools of one MCP server (see module docstring).

    Args:
        client: Connected MCP client session.
        server: Stable operator-chosen server identifier (used in pins and taint sources).
        policies: Tools to expose and their argument policies.
        registry: Registry receiving the accepted tools.
        memory: Symbolic memory receiving the raw (untrusted) descriptions.
        pins: Approved manifest digests; updated in place under trust-on-first-use.
        scanner: Poisoning scanner (default configuration if omitted).
        trust_on_first_use: Pin clean, never-seen tools instead of rejecting them.
        audit: Optional audit log for manifest decisions.

    Returns:
        A report; rejected tools are not registered.
    """
    scanner = scanner or PoisoningScanner()
    wanted: Mapping[str, MCPToolPolicy] = {p.name: p for p in policies}
    listing = await client.list_tools()
    upstream_names = [t.name for t in listing.tools]
    report = MCPImportReport()

    for tool in listing.tools:
        manifest = ToolManifest.from_parts(server, tool.name, tool.description, tool.input_schema)
        raw_pointer = memory.store(
            manifest.description,
            Provenance.untrusted(f"mcp:{server}:tool_description"),
            label=f"upstream description of {manifest.key}",
        )
        report.raw_descriptions[tool.name] = raw_pointer
        policy = wanted.get(tool.name)
        if policy is None:
            report.ignored.append(tool.name)
            continue
        try:
            _vet(manifest, policy, pins, scanner, upstream_names, trust_on_first_use)
        except ToolPoisoningDetected as exc:
            report.rejected[tool.name] = exc
            if audit is not None:
                audit.record(EventKind.MANIFEST, Decision.DENY, str(exc), tool=manifest.key)
            continue
        registry.register(
            ToolSpec(
                name=policy.name,
                description=policy.description,
                arguments=policy.arguments,
                function=_make_caller(client, tool.name),
                output_trust=policy.output_trust,
                raw_description=raw_pointer,
            )
        )
        report.registered.append(tool.name)
        if audit is not None:
            audit.record(
                EventKind.MANIFEST,
                Decision.ALLOW,
                "tool manifest verified",
                tool=manifest.key,
                digest=manifest.digest(),
            )
    report.missing = sorted(set(wanted) - set(upstream_names))
    return report


def _vet(  # noqa: PLR0917 - private helper with a single call site
    manifest: ToolManifest,
    policy: MCPToolPolicy,
    pins: ManifestPinStore,
    scanner: PoisoningScanner,
    upstream_names: Sequence[str],
    trust_on_first_use: bool,
) -> None:
    first_use = False
    try:
        pins.verify(manifest)
    except UnpinnedToolError:
        if not trust_on_first_use:
            raise
        first_use = True
    findings = scanner.scan(manifest, other_tool_names=upstream_names)
    if findings:
        summary = "; ".join(f"{f.rule}@{f.location}" for f in findings)
        raise ToolPoisoningDetected(f"tool {manifest.key} has poisoning indicators: {summary}")
    check_schema_contract(manifest, (a.name for a in policy.arguments))
    if first_use:
        pins.pin(manifest)
