from __future__ import annotations

import pytest

from dual_llm_guard import (
    ConfigurationError,
    Provenance,
    Purpose,
    QuarantineBreach,
    QuarantinedLLM,
    QuarantineOutputError,
    Redacted,
    ScriptedLLM,
    SymbolicMemory,
    Trust,
)
from dual_llm_guard.quarantined_llm import QuarantineInput

from .helpers import INJECTION


def _input(memory: SymbolicMemory, text: str, provenance: Provenance) -> QuarantineInput:
    ptr = memory.store(text, provenance, label="in")
    return QuarantineInput(ptr, Redacted(text), provenance)


def test_refuses_tools() -> None:
    memory = SymbolicMemory()
    with pytest.raises(QuarantineBreach):
        QuarantinedLLM(ScriptedLLM(responses=["x"]), memory.writer(), tools=[lambda: None])
    with pytest.raises(QuarantineBreach):
        QuarantinedLLM(ScriptedLLM(responses=["x"]), memory.writer(), tools=[])


def test_requires_write_only_memory() -> None:
    with pytest.raises(ConfigurationError, match="MemoryWriter"):
        QuarantinedLLM(ScriptedLLM(responses=["x"]), SymbolicMemory())  # type: ignore[arg-type]


def test_is_sealed_after_construction() -> None:
    q = QuarantinedLLM(ScriptedLLM(responses=["x"]), SymbolicMemory().writer())
    with pytest.raises(QuarantineBreach, match="sealed"):
        q.tools = ["send_email"]
    with pytest.raises(QuarantineBreach):
        q._client = ScriptedLLM(responses=["y"])
    assert repr(q) == "QuarantinedLLM(<no tools, write-only memory>)"


async def test_output_is_stored_tainted_and_only_pointer_returned() -> None:
    memory = SymbolicMemory()
    reader = ScriptedLLM(responses=["  compromised summary  "])
    q = QuarantinedLLM(reader, memory.writer())
    item = _input(memory, INJECTION, Provenance.untrusted("tool:read"))
    out = await q.process("Summarise.", [item], label="summary")
    meta = memory.describe(out)
    assert meta.trust is Trust.UNTRUSTED
    assert meta.sources == {"tool:read", "llm:quarantined"}
    assert memory.provenance(out).derived_from == {item.pointer.token}
    cap = memory.mint_capability("test")
    assert memory.resolve(out, cap, Purpose.USER_DISPLAY) == "compromised summary"
    # the data really reached the quarantined model, inside boundary markers
    prompt = reader.transcript[0][-1].content
    assert INJECTION in prompt
    assert prompt.startswith("TASK: Summarise.")
    assert "<<DATA " in prompt
    assert "<<END " in prompt


async def test_output_untrusted_even_for_trusted_inputs() -> None:
    memory = SymbolicMemory()
    q = QuarantinedLLM(ScriptedLLM(responses=["ok"]), memory.writer())
    out = await q.process("Echo.", [_input(memory, "hello", Provenance.trusted("user"))])
    assert memory.describe(out).trust is Trust.UNTRUSTED


async def test_multiple_inputs_join_provenance() -> None:
    memory = SymbolicMemory()
    q = QuarantinedLLM(ScriptedLLM(responses=["ok"]), memory.writer())
    a = _input(memory, "a", Provenance.untrusted("web"))
    b = _input(memory, "b", Provenance.trusted("user"))
    out = await q.process("Merge.", [a, b])
    assert memory.provenance(out).sources == {"web", "user", "llm:quarantined"}
    assert memory.provenance(out).derived_from == {a.pointer.token, b.pointer.token}


@pytest.mark.parametrize(
    ("kind", "reply", "ok"),
    [
        ("email", "alice@example.com", True),
        ("email", "alice@example.com; bob@evil.com", False),
        ("email", "Sure! The address is alice@example.com", False),
        ("boolean", "TRUE", True),
        ("boolean", "false", True),
        ("boolean", "yes", False),
        ("integer", "-42", True),
        ("integer", "42 apples", False),
        ("text", "anything at all", True),
    ],
)
async def test_output_kind_validation(kind: str, reply: str, ok: bool) -> None:
    memory = SymbolicMemory()
    q = QuarantinedLLM(ScriptedLLM(responses=[reply]), memory.writer())
    item = _input(memory, "data", Provenance.untrusted("web"))
    if ok:
        await q.process("Extract.", [item], output_kind=kind)  # type: ignore[arg-type]
    else:
        with pytest.raises(QuarantineOutputError) as excinfo:
            await q.process("Extract.", [item], output_kind=kind)  # type: ignore[arg-type]
        assert reply not in str(excinfo.value)


async def test_requires_inputs() -> None:
    q = QuarantinedLLM(ScriptedLLM(responses=["x"]), SymbolicMemory().writer())
    with pytest.raises(ConfigurationError):
        await q.process("Nothing.", [])
