from __future__ import annotations

import pickle
import re
import threading

import pytest

from dual_llm_guard import (
    Provenance,
    Purpose,
    Redacted,
    SymbolicMemory,
    SymbolicPointer,
    Trust,
    UnauthorizedDeclassification,
    UnknownPointerError,
)
from dual_llm_guard.symbolic_memory import DeclassificationCapability, find_pointer_tokens

SECRET = "the launch code is 0000-1234-TOP-SECRET, do not share it"


@pytest.fixture
def memory() -> SymbolicMemory:
    return SymbolicMemory()


def test_pointer_format_is_opaque_uuid(memory: SymbolicMemory) -> None:
    ptr = memory.store(SECRET, Provenance.untrusted("web"), label="page")
    assert re.fullmatch(r"\$VAR_[0-9a-f]{32}", ptr.token)
    assert str(ptr) == ptr.token
    assert repr(ptr) == f"SymbolicPointer({ptr.token!r})"
    assert SECRET not in repr(ptr)


def test_same_content_yields_distinct_pointers(memory: SymbolicMemory) -> None:
    a = memory.store("x", Provenance.untrusted("web"), label="a")
    b = memory.store("x", Provenance.untrusted("web"), label="b")
    assert a != b


@pytest.mark.parametrize(
    "token", ["$VAR_1", "VAR_" + "a" * 32, "$VAR_" + "A" * 32, "$VAR_" + "g" * 32, " $VAR_" + "a" * 32, ""]
)
def test_malformed_pointers_rejected(token: str) -> None:
    with pytest.raises(ValueError, match="malformed"):
        SymbolicPointer(token)


def test_pointer_is_frozen(memory: SymbolicMemory) -> None:
    ptr = memory.store("x", Provenance.trusted("user"), label="a")
    with pytest.raises(AttributeError):
        ptr.token = "$VAR_" + "0" * 32  # type: ignore[misc]


def test_memory_repr_and_len_do_not_leak(memory: SymbolicMemory) -> None:
    memory.store(SECRET, Provenance.untrusted("web"), label="page")
    assert repr(memory) == "SymbolicMemory(entries=1)"
    assert len(memory) == 1


def test_memory_is_not_enumerable(memory: SymbolicMemory) -> None:
    memory.store(SECRET, Provenance.untrusted("web"), label="page")
    with pytest.raises(TypeError, match="enumeration"):
        iter(memory)


def test_contains(memory: SymbolicMemory) -> None:
    ptr = memory.store("x", Provenance.untrusted("web"), label="a")
    assert ptr in memory
    assert SymbolicPointer.new() not in memory
    assert ptr.token not in memory  # raw strings are not pointers


def test_describe_is_content_free(memory: SymbolicMemory) -> None:
    ptr = memory.store(SECRET, Provenance.untrusted("web"), label="page")
    meta = memory.describe(ptr)
    assert meta.trust is Trust.UNTRUSTED
    assert meta.sources == {"web"}
    assert meta.label == "page"
    assert SECRET not in repr(meta)


def test_store_rejects_non_text(memory: SymbolicMemory) -> None:
    with pytest.raises(TypeError):
        memory.store(b"bytes", Provenance.untrusted("web"), label="x")  # type: ignore[arg-type]


def test_capability_can_only_be_minted_once(memory: SymbolicMemory) -> None:
    cap = memory.mint_capability("monitor")
    assert cap.holder == "monitor"
    assert "monitor" in repr(cap)
    with pytest.raises(UnauthorizedDeclassification):
        memory.mint_capability("attacker")


def test_resolve_with_capability(memory: SymbolicMemory) -> None:
    ptr = memory.store(SECRET, Provenance.untrusted("web"), label="page")
    cap = memory.mint_capability("monitor")
    assert memory.resolve(ptr, cap, Purpose.TOOL_ARGUMENT) == SECRET


def test_resolve_requires_valid_purpose(memory: SymbolicMemory) -> None:
    ptr = memory.store(SECRET, Provenance.untrusted("web"), label="page")
    cap = memory.mint_capability("monitor")
    with pytest.raises(TypeError):
        memory.resolve(ptr, cap, "tool_argument")  # type: ignore[arg-type]


def test_capability_from_other_memory_is_rejected(memory: SymbolicMemory) -> None:
    ptr = memory.store(SECRET, Provenance.untrusted("web"), label="page")
    other_cap = SymbolicMemory().mint_capability("other")
    with pytest.raises(UnauthorizedDeclassification):
        memory.resolve(ptr, other_cap, Purpose.TOOL_ARGUMENT)


def test_non_capability_objects_rejected(memory: SymbolicMemory) -> None:
    ptr = memory.store(SECRET, Provenance.untrusted("web"), label="page")
    with pytest.raises(UnauthorizedDeclassification):
        memory.resolve(ptr, object(), Purpose.TOOL_ARGUMENT)  # type: ignore[arg-type]


def test_capability_cannot_be_constructed_directly(memory: SymbolicMemory) -> None:
    with pytest.raises(UnauthorizedDeclassification):
        DeclassificationCapability(object(), "id", b"secret", "forger")


def test_capability_cannot_be_pickled(memory: SymbolicMemory) -> None:
    cap = memory.mint_capability("monitor")
    with pytest.raises(TypeError, match="pickled"):
        pickle.dumps(cap)


def test_unknown_pointer(memory: SymbolicMemory) -> None:
    cap = memory.mint_capability("monitor")
    with pytest.raises(UnknownPointerError):
        memory.resolve(SymbolicPointer.new(), cap, Purpose.TOOL_ARGUMENT)
    with pytest.raises(UnknownPointerError):
        memory.describe(SymbolicPointer.new())


def test_non_pointer_lookup_is_type_error(memory: SymbolicMemory) -> None:
    with pytest.raises(TypeError):
        memory.provenance("$VAR_" + "0" * 32)  # type: ignore[arg-type]


def test_writer_is_write_only(memory: SymbolicMemory) -> None:
    writer = memory.writer()
    ptr = writer.store("hello", Provenance.untrusted("x"), label="y")
    assert ptr in memory
    assert not hasattr(writer, "resolve")
    assert repr(writer) == "MemoryWriter(<write-only>)"


def test_redacted_hides_content() -> None:
    r = Redacted(SECRET)
    assert SECRET not in repr(r)
    assert SECRET not in str(r)
    assert SECRET not in f"{r}"
    assert r.reveal() == SECRET


class TestFingerprints:
    def test_detects_verbatim_fragment(self, memory: SymbolicMemory) -> None:
        memory.store(SECRET, Provenance.untrusted("web"), label="page")
        assert memory.contains_untrusted_fragment(f"Please plan: {SECRET[5:40]} thanks")

    def test_normalises_case_and_whitespace(self, memory: SymbolicMemory) -> None:
        memory.store(SECRET, Provenance.untrusted("web"), label="page")
        mangled = SECRET.upper().replace(" ", "  \n ")
        assert memory.contains_untrusted_fragment(mangled)

    def test_unrelated_text_is_clean(self, memory: SymbolicMemory) -> None:
        memory.store(SECRET, Provenance.untrusted("web"), label="page")
        assert not memory.contains_untrusted_fragment("Summarise my latest e-mail for my boss.")

    def test_trusted_values_are_not_fingerprinted(self, memory: SymbolicMemory) -> None:
        memory.store(SECRET, Provenance.trusted("user"), label="note")
        assert not memory.contains_untrusted_fragment(SECRET)

    def test_short_values_are_not_fingerprinted(self, memory: SymbolicMemory) -> None:
        memory.store("yes", Provenance.untrusted("web"), label="x")
        assert not memory.contains_untrusted_fragment("yes, of course")

    def test_window_lower_bound(self) -> None:
        with pytest.raises(ValueError, match="fingerprint_window"):
            SymbolicMemory(fingerprint_window=4)

    def test_keyed_fingerprints_differ_between_memories(self) -> None:
        a, b = SymbolicMemory(), SymbolicMemory()
        a.store(SECRET, Provenance.untrusted("web"), label="x")
        assert a.contains_untrusted_fragment(SECRET)
        assert not b.contains_untrusted_fragment(SECRET)


def test_find_pointer_tokens() -> None:
    p1, p2 = SymbolicPointer.new(), SymbolicPointer.new()
    assert find_pointer_tokens(f"use {p1} and {p2}, then {p1}") == [p1.token, p2.token, p1.token]
    assert find_pointer_tokens("$VAR_123 nothing here") == []


def test_concurrent_stores_are_consistent(memory: SymbolicMemory) -> None:
    pointers: list[SymbolicPointer] = []
    lock = threading.Lock()

    def worker(n: int) -> None:
        local = [memory.store(f"value {n}-{i} " * 4, Provenance.untrusted("w"), label="x") for i in range(200)]
        with lock:
            pointers.extend(local)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(memory) == 16 * 200
    assert len({p.token for p in pointers}) == 16 * 200
    cap = memory.mint_capability("monitor")
    assert memory.resolve(pointers[0], cap, Purpose.USER_DISPLAY).startswith("value ")
