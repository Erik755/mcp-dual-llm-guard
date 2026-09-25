from __future__ import annotations

import json

import pytest

from dual_llm_guard import AuditLog, Decision, EventKind


def test_record_and_query() -> None:
    log = AuditLog()
    log.record(EventKind.PLAN, Decision.ALLOW, "ok", step="s1")
    log.record(EventKind.TAINT_FLOW, Decision.DENY, "blocked")
    assert len(log) == 2
    assert [e.kind for e in log] == [EventKind.PLAN, EventKind.TAINT_FLOW]
    assert [e.message for e in log.denials()] == ["blocked"]
    assert log.events[0].details["step"] == "s1"


def test_events_are_immutable() -> None:
    log = AuditLog()
    event = log.record(EventKind.PLAN, Decision.ALLOW, "ok", step="s1")
    with pytest.raises(TypeError):
        event.details["step"] = "x"  # type: ignore[index]
    with pytest.raises(AttributeError):
        event.message = "changed"  # type: ignore[misc]


def test_jsonl_roundtrip() -> None:
    log = AuditLog()
    log.record(EventKind.DECLASSIFY, Decision.ALLOW, "resolved", pointer="$VAR_1")
    lines = log.to_jsonl().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["kind"] == "declassify"
    assert data["decision"] == "allow"
    assert data["details"] == {"pointer": "$VAR_1"}
    assert isinstance(data["timestamp"], float)
