"""Append-only audit trail of every reference-monitor decision.

Events never contain untrusted content: only pointer tokens, tool/argument
names, provenance source names and policy decisions. This keeps the log safe
to ship to a SIEM and safe to show to humans (a log viewer must not become a
new injection surface).
"""

from __future__ import annotations

import enum
import json
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

__all__ = ["AuditEvent", "AuditLog", "Decision", "EventKind"]


class Decision(enum.Enum):
    """Outcome of a policy decision."""

    ALLOW = "allow"
    DENY = "deny"


class EventKind(enum.Enum):
    """Category of an audit event."""

    INGEST = "ingest"
    CONTEXT_CHECK = "context_check"
    PLAN = "plan"
    QUARANTINE_READ = "quarantine_read"
    QUARANTINE_OUTPUT = "quarantine_output"
    TOOL_CALL = "tool_call"
    TAINT_FLOW = "taint_flow"
    APPROVAL = "approval"
    DECLASSIFY = "declassify"
    TOOL_RESULT = "tool_result"
    DISPLAY = "display"
    MANIFEST = "manifest"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One immutable audit record."""

    kind: EventKind
    decision: Decision
    message: str
    details: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable representation."""
        return {
            "timestamp": self.timestamp,
            "kind": self.kind.value,
            "decision": self.decision.value,
            "message": self.message,
            "details": dict(self.details),
        }


class AuditLog:
    """Thread-safe, append-only list of :class:`AuditEvent`."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def record(
        self,
        kind: EventKind,
        decision: Decision,
        message: str,
        **details: str,
    ) -> AuditEvent:
        """Append an event and return it."""
        event = AuditEvent(kind, decision, message, MappingProxyType(dict(details)))
        with self._lock:
            self._events.append(event)
        return event

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        """Snapshot of all events recorded so far."""
        with self._lock:
            return tuple(self._events)

    def denials(self) -> tuple[AuditEvent, ...]:
        """Only the events whose decision was :attr:`Decision.DENY`."""
        return tuple(e for e in self.events if e.decision is Decision.DENY)

    def to_jsonl(self) -> str:
        """Serialise the log as JSON Lines."""
        return "\n".join(json.dumps(e.to_dict(), sort_keys=True) for e in self.events)

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(self.events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
