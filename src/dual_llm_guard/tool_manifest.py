"""Tool-poisoning defences for MCP tool manifests.

In MCP, a server advertises tools as ``(name, description, inputSchema)``. Agent
frameworks usually paste those descriptions straight into the model's prompt,
which makes every connected server a prompt-injection vector ("tool poisoning")
-- and a server can silently change a description after the user approved it
("rug pull"). This module treats manifests as **untrusted data**:

1. :class:`ManifestPinStore` pins the SHA-256 digest of each reviewed manifest
   (lock-file style) and refuses changed or never-reviewed tools.
2. :class:`PoisoningScanner` flags well-known poisoning indicators (hidden
   Unicode, instruction-like markup, references to secrets, cross-tool
   shadowing). It is a tripwire, not the primary defence.
3. :func:`check_schema_contract` requires the upstream schema to match the
   operator's declared arguments, so parameter names/descriptions cannot smuggle
   instructions either.

The primary defence is architectural and lives in
:mod:`dual_llm_guard.mcp_adapter`: the privileged planner only ever sees the
operator-written description; the upstream description is stored in symbolic
memory as untrusted data.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .exceptions import ToolManifestChanged, ToolPoisoningDetected, UnpinnedToolError
from .policy import IDENTIFIER

__all__ = [
    "ManifestPinStore",
    "PoisoningFinding",
    "PoisoningScanner",
    "ToolManifest",
    "check_schema_contract",
]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class ToolManifest:
    """An upstream tool definition, captured immutably.

    ``input_schema`` is stored as canonical JSON so the manifest is hashable and
    cannot be mutated after pinning.
    """

    server: str
    name: str
    description: str
    schema_json: str

    @classmethod
    def from_parts(
        cls, server: str, name: str, description: str | None, input_schema: Mapping[str, Any]
    ) -> ToolManifest:
        """Build a manifest from the raw fields reported by an MCP server."""
        return cls(server, name, description or "", _canonical_json(dict(input_schema)))

    @property
    def input_schema(self) -> dict[str, Any]:
        """A fresh copy of the JSON schema."""
        schema: dict[str, Any] = json.loads(self.schema_json)
        return schema

    @property
    def key(self) -> str:
        """Stable identifier ``server/name``."""
        return f"{self.server}/{self.name}"

    def digest(self) -> str:
        """SHA-256 over the canonical JSON of the whole manifest."""
        payload = _canonical_json(
            {
                "server": self.server,
                "name": self.name,
                "description": self.description,
                "input_schema": self.input_schema,
            }
        )
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def __repr__(self) -> str:
        # The description is untrusted; keep it out of reprs and logs.
        return f"ToolManifest(key={self.key!r}, digest={self.digest()!r})"


class ManifestPinStore:
    """Lock-file of approved manifest digests (``server/name -> sha256:...``)."""

    def __init__(self, pins: Mapping[str, str] | None = None) -> None:
        self._pins: dict[str, str] = dict(pins or {})
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: str | Path) -> ManifestPinStore:
        """Load pins from a JSON file (missing file -> empty store)."""
        file = Path(path)
        if not file.exists():
            return cls()
        data = json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            raise ValueError(f"{file} is not a valid pin file")
        return cls(data)

    def save(self, path: str | Path) -> None:
        """Write pins as pretty, sorted JSON (friendly to code review)."""
        with self._lock:
            content = json.dumps(self._pins, indent=2, sort_keys=True)
        Path(path).write_text(content + "\n", encoding="utf-8")

    def pin(self, manifest: ToolManifest) -> str:
        """Approve ``manifest`` and return its digest."""
        digest = manifest.digest()
        with self._lock:
            self._pins[manifest.key] = digest
        return digest

    def verify(self, manifest: ToolManifest) -> None:
        """Raise unless ``manifest`` matches its pinned digest.

        Raises:
            UnpinnedToolError: The tool was never reviewed.
            ToolManifestChanged: The tool changed since it was pinned (rug pull).
        """
        with self._lock:
            expected = self._pins.get(manifest.key)
        if expected is None:
            raise UnpinnedToolError(f"tool {manifest.key} is not pinned")
        actual = manifest.digest()
        if actual != expected:
            raise ToolManifestChanged(f"tool {manifest.key} changed after approval: pinned {expected}, got {actual}")

    def is_pinned(self, key: str) -> bool:
        """Whether ``server/name`` has a pin."""
        with self._lock:
            return key in self._pins

    def __iter__(self) -> Iterator[tuple[str, str]]:
        with self._lock:
            return iter(sorted(self._pins.items()))


@dataclass(frozen=True, slots=True)
class PoisoningFinding:
    """One indicator found by :class:`PoisoningScanner`.

    ``detail`` is generated by the scanner and never echoes the offending text,
    so findings are safe to log.
    """

    rule: str
    location: str
    detail: str


# Instruction-like patterns documented in public tool-poisoning research
# (hidden <IMPORTANT> blocks, "ignore previous instructions", secrecy requests,
# file-exfiltration targets). Kept deliberately specific to limit false positives.
_SUSPICIOUS_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("instruction_markup", re.compile(r"<\s*/?\s*(important|system|instructions?|secret)\b", re.I)),
    (
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all)\b"
            r".{0,20}\b(instructions?|prompts?|rules)\b",
            re.I | re.S,
        ),
    ),
    (
        "conceal_from_user",
        re.compile(r"\b(do\s+not|don't|never)\s+(tell|mention|inform|reveal|show)\b.{0,30}\buser\b", re.I | re.S),
    ),
    (
        "secret_file_reference",
        re.compile(
            r"(~|\$HOME|%USERPROFILE%)?[/\\]\.(ssh|aws|gnupg|kube|docker)\b|\bid_(rsa|ed25519|ecdsa)\b"
            r"|(^|[/\\\s])\.env\b|\bmcp\.json\b|\bcredentials?\.json\b",
            re.I,
        ),
    ),
    (
        "tool_ordering_hijack",
        re.compile(r"\b(before|after|instead\s+of)\s+(using|calling|invoking)\s+(this|any|the\s+other)\b", re.I),
    ),
)


class PoisoningScanner:
    """Heuristic scanner for poisoned MCP tool manifests.

    Args:
        max_description_length: Descriptions longer than this are flagged
            (hidden payloads are often padded far below the visible fold).
    """

    def __init__(self, *, max_description_length: int = 1024) -> None:
        self._max_len = max_description_length

    def scan(self, manifest: ToolManifest, *, other_tool_names: Iterable[str] = ()) -> list[PoisoningFinding]:
        """Return every finding for ``manifest`` (empty list means no indicator)."""
        findings: list[PoisoningFinding] = []
        if not IDENTIFIER.match(manifest.name):
            findings.append(PoisoningFinding("invalid_name", "name", "tool name is not a plain identifier"))
        if len(manifest.description) > self._max_len:
            findings.append(
                PoisoningFinding(
                    "oversized_description",
                    "description",
                    f"{len(manifest.description)} chars > {self._max_len}",
                )
            )
        others = {n for n in other_tool_names if n != manifest.name}
        for location, text in self._texts(manifest):
            findings.extend(self._scan_text(location, text, others))
        return findings

    @staticmethod
    def _texts(manifest: ToolManifest) -> Iterator[tuple[str, str]]:
        """Yield every free-text field: description plus all strings/keys in the schema."""
        yield "description", manifest.description

        def walk(node: Any, path: str) -> Iterator[tuple[str, str]]:
            if isinstance(node, str):
                yield path, node
            elif isinstance(node, dict):
                for key, value in node.items():
                    yield f"{path}.<key>", str(key)
                    yield from walk(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    yield from walk(value, f"{path}[{index}]")

        yield from walk(manifest.input_schema, "input_schema")

    @staticmethod
    def _scan_text(location: str, text: str, other_tools: set[str]) -> Iterator[PoisoningFinding]:
        for offset, char in enumerate(text):
            # Category Cf = format characters: zero-width spaces/joiners, bidi
            # overrides, Unicode tag characters (U+E0000 block), BOM, etc.
            if unicodedata.category(char) == "Cf":
                yield PoisoningFinding(
                    "hidden_unicode", location, f"format character U+{ord(char):04X} at offset {offset}"
                )
                break
        for rule, pattern in _SUSPICIOUS_PATTERNS:
            if pattern.search(text):
                yield PoisoningFinding(rule, location, f"matched rule {rule}")
        for name in sorted(other_tools):
            if re.search(rf"\b{re.escape(name)}\b", text):
                yield PoisoningFinding("cross_tool_reference", location, f"mentions other tool {name!r}")


def check_schema_contract(manifest: ToolManifest, declared_arguments: Iterable[str]) -> None:
    """Require the upstream input schema to match the operator's declared arguments.

    The schema must be an object whose property names are exactly the declared
    argument names, each typed ``string``, with every required property declared.

    Raises:
        ToolPoisoningDetected: On any mismatch.
    """
    declared = set(declared_arguments)
    schema = manifest.input_schema
    if schema.get("type", "object") != "object":
        raise ToolPoisoningDetected(f"tool {manifest.key}: input schema is not an object")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ToolPoisoningDetected(f"tool {manifest.key}: malformed properties")
    upstream = set(properties)
    if upstream != declared:
        extra = sorted(n for n in upstream - declared if IDENTIFIER.match(n))
        raise ToolPoisoningDetected(
            f"tool {manifest.key}: schema arguments differ from policy "
            f"(missing={sorted(declared - upstream)}, unexpected={extra}"
            f"{', plus non-identifier names' if any(not IDENTIFIER.match(n) for n in upstream) else ''})"
        )
    for name, prop in properties.items():
        if not isinstance(prop, dict) or prop.get("type") != "string":
            raise ToolPoisoningDetected(f"tool {manifest.key}: argument {name!r} must be a string")
    required = schema.get("required", [])
    if not isinstance(required, list) or not set(required) <= declared:
        raise ToolPoisoningDetected(f"tool {manifest.key}: required arguments not declared by policy")
