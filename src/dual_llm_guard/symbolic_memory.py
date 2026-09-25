"""Symbolic memory: the vault that keeps untrusted data away from the planner.

The privileged (tool-using) LLM must never *read* untrusted content, yet it has
to *reason about* and *route* that content (e.g. "summarise $VAR_1 and e-mail
the summary to my boss"). The symbolic memory makes this possible:

* Every value is stored exactly once and a :class:`SymbolicPointer` is returned.
  The pointer is an opaque, unguessable token (``$VAR_<uuid4 hex>``) that carries
  **no** information about the content (not even its length).
* Values are immutable strings with an immutable :class:`~dual_llm_guard.taint.Provenance`.
* Reading a value back requires a :class:`DeclassificationCapability`. Exactly one
  capability can be minted per memory instance, and it is meant to be held by the
  reference monitor's declassification choke point only.
* Nothing in this module prints content: ``repr``/``str`` of memories, entries and
  :class:`Redacted` wrappers are content-free.
* To let the reference monitor detect content leaking into the planner's prompt,
  the memory keeps *keyed fingerprints* (BLAKE2b of normalised sliding windows) of
  untrusted values. Fingerprints are one-way; they allow a membership test without
  exposing the text.

.. note::
   Python offers no hard encapsulation: code running in the same interpreter can
   always reach private attributes. The capability scheme defends against
   *accidental* and *LLM-driven* misuse (the realistic threat: an agent framework
   wiring untrusted data into a prompt), not against malicious code in-process.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import re
import secrets
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

from .exceptions import UnauthorizedDeclassification, UnknownPointerError
from .taint import Provenance, Trust

__all__ = [
    "POINTER_PATTERN",
    "DeclassificationCapability",
    "MemoryWriter",
    "PointerMetadata",
    "Purpose",
    "Redacted",
    "SymbolicMemory",
    "SymbolicPointer",
    "find_pointer_tokens",
]

#: Canonical textual form of a pointer: ``$VAR_`` followed by 32 lowercase hex digits
#: (a UUID4 without dashes, i.e. 122 bits of randomness).
POINTER_PATTERN: Final[re.Pattern[str]] = re.compile(r"\$VAR_[0-9a-f]{32}")
_POINTER_FULL: Final[re.Pattern[str]] = re.compile(r"\A\$VAR_[0-9a-f]{32}\Z")
_WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")

#: Sentinel preventing construction of capabilities outside this module.
_MINT_KEY: Final[object] = object()


def find_pointer_tokens(text: str) -> list[str]:
    """Return every pointer-shaped token found in ``text`` (in order, with duplicates)."""
    return POINTER_PATTERN.findall(text)


@dataclass(frozen=True, slots=True)
class SymbolicPointer:
    """Opaque reference to a value stored in a :class:`SymbolicMemory`.

    A pointer is just a random identifier: it holds no reference to the memory
    or the value, so it can be freely shown to the privileged LLM, logged and
    serialised. Possessing a pointer does **not** grant the right to read it.
    """

    token: str

    def __post_init__(self) -> None:
        if not isinstance(self.token, str) or not _POINTER_FULL.match(self.token):
            raise ValueError("malformed symbolic pointer")

    @classmethod
    def new(cls) -> SymbolicPointer:
        """Generate a fresh pointer backed by a random UUID4."""
        return cls(f"$VAR_{uuid.uuid4().hex}")

    def __str__(self) -> str:
        return self.token

    def __repr__(self) -> str:
        return f"SymbolicPointer({self.token!r})"


class Purpose(enum.Enum):
    """Why a value is being resolved (recorded for auditing)."""

    TOOL_ARGUMENT = "tool_argument"
    """Binding an argument of a tool call: the declassification choke point."""

    QUARANTINED_INPUT = "quarantined_input"
    """Feeding the quarantined LLM (output stays tainted, so this is not a declassification)."""

    USER_DISPLAY = "user_display"
    """Rendering the final answer to the human user."""


@dataclass(frozen=True, slots=True)
class PointerMetadata:
    """Content-free facts about a stored value that are safe to show the planner."""

    pointer: SymbolicPointer
    trust: Trust
    sources: frozenset[str]
    label: str
    """Short, trusted-code-generated description (e.g. ``"output of step s1"``)."""


class Redacted:
    """A string wrapper whose ``repr``/``str`` never reveal the content.

    Used to hand resolved untrusted text to the quarantined LLM without the
    risk of it being accidentally formatted into logs or other prompts.
    """

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        self.__value = value

    def reveal(self) -> str:
        """Return the wrapped text. Call sites are intentionally easy to grep for."""
        return self.__value

    def __repr__(self) -> str:
        return "Redacted(<hidden>)"

    __str__ = __repr__


class DeclassificationCapability:
    """Unforgeable-by-convention token that authorises reading a memory.

    Instances can only be created by :meth:`SymbolicMemory.mint_capability`,
    which succeeds exactly once per memory. The capability is bound to that
    specific memory; presenting it to another memory fails.
    """

    __slots__ = ("_holder", "_memory_id", "_secret")

    def __init__(self, key: object, memory_id: str, secret: bytes, holder: str) -> None:
        if key is not _MINT_KEY:
            raise UnauthorizedDeclassification("capabilities can only be minted by SymbolicMemory.mint_capability()")
        self._memory_id = memory_id
        self._secret = secret
        self._holder = holder

    @property
    def holder(self) -> str:
        """Name of the component the capability was issued to (for audit logs)."""
        return self._holder

    def __repr__(self) -> str:
        return f"DeclassificationCapability(holder={self._holder!r})"

    def __reduce__(self) -> str | tuple[object, ...]:
        # Capabilities must not be serialised or copied out of the process.
        raise TypeError("DeclassificationCapability cannot be pickled")


@dataclass(frozen=True, slots=True)
class _Entry:
    value: str
    provenance: Provenance
    label: str

    def __repr__(self) -> str:  # pragma: no cover - defensive, never formatted by the library
        return f"_Entry(<hidden>, trust={self.provenance.trust.value})"


class MemoryWriter:
    """Write-only facade over a :class:`SymbolicMemory`.

    Handed to components (such as the quarantined LLM) that must be able to
    *produce* values but must never *read* any.
    """

    __slots__ = ("_memory",)

    def __init__(self, memory: SymbolicMemory) -> None:
        self._memory = memory

    def store(self, value: str, provenance: Provenance, *, label: str) -> SymbolicPointer:
        """Store ``value`` and return its pointer (see :meth:`SymbolicMemory.store`)."""
        return self._memory.store(value, provenance, label=label)

    def __repr__(self) -> str:
        return "MemoryWriter(<write-only>)"


class SymbolicMemory:
    """Thread-safe, append-only store mapping opaque pointers to tainted values.

    Args:
        fingerprint_window: Length (in normalised characters) of the sliding
            windows used to fingerprint untrusted values. Any verbatim fragment
            at least this long that leaks into the planner context is detected.
            Values shorter than the window are not fingerprinted (see
            :meth:`contains_untrusted_fragment`).
    """

    def __init__(self, *, fingerprint_window: int = 24) -> None:
        if fingerprint_window < 8:
            raise ValueError("fingerprint_window must be >= 8 to avoid false positives")
        self._id = uuid.uuid4().hex
        self._secret = secrets.token_bytes(32)
        self._fp_key = secrets.token_bytes(32)
        self._window = fingerprint_window
        self._entries: dict[str, _Entry] = {}
        self._fingerprints: set[bytes] = set()
        self._capability_minted = False
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ writing
    def store(self, value: str, provenance: Provenance, *, label: str) -> SymbolicPointer:
        """Store an immutable value and return a fresh opaque pointer.

        Args:
            value: The raw text. Stored as-is; never returned without a capability.
            provenance: Taint label of the value.
            label: Short description generated by trusted code (shown to the planner).
                It must not contain untrusted text.

        Returns:
            A newly generated pointer; storing the same text twice yields two
            different pointers, so pointers cannot be used as a content oracle.
        """
        if not isinstance(value, str):
            raise TypeError("SymbolicMemory stores text only")
        pointer = SymbolicPointer.new()
        entry = _Entry(value=value, provenance=provenance, label=label)
        prints = self._fingerprint(value) if provenance.is_untrusted else set()
        with self._lock:
            # A UUID4 collision is astronomically unlikely, but a vault must not
            # silently overwrite data, so we check anyway.
            while pointer.token in self._entries:  # pragma: no cover
                pointer = SymbolicPointer.new()
            self._entries[pointer.token] = entry
            self._fingerprints |= prints
        return pointer

    def writer(self) -> MemoryWriter:
        """Return a write-only facade for producers such as the quarantined LLM."""
        return MemoryWriter(self)

    # --------------------------------------------------------------- metadata
    def describe(self, pointer: SymbolicPointer) -> PointerMetadata:
        """Return content-free metadata about ``pointer``.

        Raises:
            UnknownPointerError: If the pointer was not issued by this memory.
        """
        entry = self._get(pointer)
        return PointerMetadata(
            pointer=pointer,
            trust=entry.provenance.trust,
            sources=entry.provenance.sources,
            label=entry.label,
        )

    def provenance(self, pointer: SymbolicPointer) -> Provenance:
        """Return the taint label of ``pointer`` (safe: contains no content)."""
        return self._get(pointer).provenance

    def __contains__(self, pointer: object) -> bool:
        if not isinstance(pointer, SymbolicPointer):
            return False
        with self._lock:
            return pointer.token in self._entries

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __iter__(self) -> Iterator[SymbolicPointer]:
        # Deliberately not iterable: enumeration of pointers is a capability we
        # do not want to hand to anybody, including the planner.
        raise TypeError("SymbolicMemory does not support enumeration")

    def __repr__(self) -> str:
        return f"SymbolicMemory(entries={len(self)})"

    # ------------------------------------------------------- declassification
    def mint_capability(self, holder: str) -> DeclassificationCapability:
        """Mint the single read capability of this memory.

        Args:
            holder: Name of the component receiving it (recorded for audit).

        Raises:
            UnauthorizedDeclassification: If a capability was already minted.
        """
        with self._lock:
            if self._capability_minted:
                raise UnauthorizedDeclassification("the declassification capability of this memory was already issued")
            self._capability_minted = True
        return DeclassificationCapability(_MINT_KEY, self._id, self._secret, holder)

    def resolve(
        self,
        pointer: SymbolicPointer,
        capability: DeclassificationCapability,
        purpose: Purpose,
    ) -> str:
        """Return the raw value behind ``pointer``.

        Only the holder of this memory's capability may call this; the reference
        monitor does so exactly when binding tool arguments, feeding the
        quarantined LLM, or rendering the final answer for the user.

        Raises:
            UnauthorizedDeclassification: If ``capability`` is not this memory's.
            UnknownPointerError: If the pointer was not issued by this memory.
        """
        self._check_capability(capability)
        if not isinstance(purpose, Purpose):
            raise TypeError("purpose must be a Purpose")
        return self._get(pointer).value

    def _check_capability(self, capability: object) -> None:
        if (
            not isinstance(capability, DeclassificationCapability)
            or capability._memory_id != self._id
            or not hmac.compare_digest(capability._secret, self._secret)
        ):
            raise UnauthorizedDeclassification("invalid declassification capability")

    # ------------------------------------------------------------ fingerprints
    def contains_untrusted_fragment(self, text: str) -> bool:
        """Check whether ``text`` contains a verbatim fragment of any untrusted value.

        Both sides are normalised (case-folded, whitespace collapsed) and cut
        into windows of ``fingerprint_window`` characters; a single shared
        window is a hit. This detects copy/paste leakage of untrusted text into
        the planner's context without the check itself needing to read values.
        Paraphrases and fragments shorter than the window are not detected --
        the primary defence is structural (the planner prompt is built only from
        trusted parts), this is a tripwire on top of it.
        """
        probe = self._fingerprint(text)
        with self._lock:
            return not self._fingerprints.isdisjoint(probe)

    def _fingerprint(self, text: str) -> set[bytes]:
        normalised = _WHITESPACE.sub(" ", text.casefold()).strip()
        k = self._window
        if len(normalised) < k:
            return set()
        return {
            hashlib.blake2b(normalised[i : i + k].encode("utf-8"), key=self._fp_key, digest_size=16).digest()
            for i in range(len(normalised) - k + 1)
        }

    # ---------------------------------------------------------------- helpers
    def _get(self, pointer: SymbolicPointer) -> _Entry:
        if not isinstance(pointer, SymbolicPointer):
            raise TypeError("expected a SymbolicPointer")
        with self._lock:
            entry = self._entries.get(pointer.token)
        if entry is None:
            raise UnknownPointerError(f"pointer {pointer.token} was not issued by this memory")
        return entry
