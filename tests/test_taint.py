from __future__ import annotations

import pytest

from dual_llm_guard import Provenance, Trust


def test_trust_join_is_least_upper_bound() -> None:
    assert Trust.TRUSTED.join(Trust.TRUSTED) is Trust.TRUSTED
    assert Trust.TRUSTED.join(Trust.UNTRUSTED) is Trust.UNTRUSTED
    assert Trust.UNTRUSTED.join(Trust.TRUSTED) is Trust.UNTRUSTED
    assert Trust.UNTRUSTED.join(Trust.UNTRUSTED) is Trust.UNTRUSTED


def test_constructors() -> None:
    assert Provenance.trusted("user") == Provenance(Trust.TRUSTED, frozenset({"user"}))
    assert Provenance.untrusted("web").is_untrusted
    assert not Provenance.trusted("user").is_untrusted


def test_provenance_requires_a_source() -> None:
    with pytest.raises(ValueError, match="at least one source"):
        Provenance(Trust.TRUSTED, frozenset())


def test_join_propagates_taint_sources_and_lineage() -> None:
    a = Provenance.trusted("user")
    b = Provenance.untrusted("tool:web").with_lineage(["$VAR_x"])
    joined = a.join([b], extra_source="llm:quarantined")
    assert joined.trust is Trust.UNTRUSTED
    assert joined.sources == {"user", "tool:web", "llm:quarantined"}
    assert joined.derived_from == {"$VAR_x"}


def test_join_of_trusted_stays_trusted() -> None:
    assert Provenance.trusted("a").join([Provenance.trusted("b")]).trust is Trust.TRUSTED


def test_provenance_is_immutable() -> None:
    p = Provenance.trusted("user")
    with pytest.raises(AttributeError):
        p.trust = Trust.UNTRUSTED  # type: ignore[misc]
