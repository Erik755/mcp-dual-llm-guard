from __future__ import annotations

import pytest

from dual_llm_guard import (
    ArgumentPolicy,
    ConfigurationError,
    ToolPolicyViolation,
    ToolRegistry,
    ToolSpec,
    UntrustedFlow,
    email_domain_allowlist,
    matches_regex,
)


def _tool(name: str = "echo", *args: ArgumentPolicy) -> ToolSpec:
    return ToolSpec(name=name, description=f"{name} tool", arguments=args, function=lambda **_: "ok")


def test_registry_allowlist() -> None:
    registry = ToolRegistry([_tool("b"), _tool("a")])
    assert "a" in registry
    assert len(registry) == 2
    assert registry.names() == {"a", "b"}
    assert registry.get("a").name == "a"
    with pytest.raises(ToolPolicyViolation, match="not allowlisted"):
        registry.get("rm_rf")


def test_duplicate_registration_rejected() -> None:
    registry = ToolRegistry([_tool("a")])
    with pytest.raises(ConfigurationError):
        registry.register(_tool("a"))


def test_catalog_is_sorted_and_operator_authored() -> None:
    registry = ToolRegistry(
        [
            _tool("zeta"),
            _tool(
                "alpha",
                ArgumentPolicy("to", "Recipient."),
                ArgumentPolicy("body", "Body.", untrusted=UntrustedFlow.ALLOW),
                ArgumentPolicy("cmd", "Command.", untrusted=UntrustedFlow.REQUIRE_APPROVAL),
            ),
        ]
    )
    catalog = registry.catalog()
    assert [c.name for c in catalog] == ["alpha", "zeta"]
    rendered = catalog[0].render()
    assert "to (trusted only)" in rendered
    assert "body (accepts untrusted refs)" in rendered
    assert "cmd (untrusted refs need human approval)" in rendered
    assert catalog[0].argument_names == {"to", "body", "cmd"}


@pytest.mark.parametrize("name", ["Send", "1tool", "send-email", "a" * 65, "", "send email"])
def test_invalid_tool_names(name: str) -> None:
    with pytest.raises(ConfigurationError):
        _tool(name)


def test_invalid_argument_config() -> None:
    with pytest.raises(ConfigurationError):
        ArgumentPolicy("Bad Name", "x")
    with pytest.raises(ConfigurationError):
        ArgumentPolicy("ok", "x", max_length=0)
    with pytest.raises(ConfigurationError):
        _tool("t", ArgumentPolicy("a", "x"), ArgumentPolicy("a", "y"))


def test_argument_lookup() -> None:
    tool = _tool("t", ArgumentPolicy("a", "x"))
    assert tool.argument("a").description == "x"
    with pytest.raises(ToolPolicyViolation):
        tool.argument("b")


def test_email_domain_allowlist() -> None:
    check = email_domain_allowlist("acme.example", "ACME.org")
    assert check("boss@acme.example")
    assert check(" Boss@Acme.Example ")
    assert check("x@acme.org")
    assert not check("attacker@evil.com")
    assert not check("boss@acme.example.evil.com")
    assert not check("boss@acme.example, attacker@evil.com")
    assert not check("not an email")
    with pytest.raises(ConfigurationError):
        email_domain_allowlist()


def test_matches_regex() -> None:
    check = matches_regex(r"[0-9]+")
    assert check("123")
    assert not check("123; rm -rf /")
