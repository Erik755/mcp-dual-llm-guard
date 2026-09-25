from __future__ import annotations

from collections.abc import Sequence

import pytest

from dual_llm_guard import (
    ApprovalRequest,
    ArgumentPolicy,
    ConfigurationError,
    Decision,
    DualLLMOrchestrator,
    EventKind,
    PrivilegedContextGuard,
    PrivilegedLLM,
    QuarantinedLLM,
    ScriptedLLM,
    SymbolicMemory,
    SymbolicPointer,
    TaintFlowViolation,
    ToolExecutionError,
    ToolPolicyViolation,
    ToolRegistry,
    ToolSpec,
    Trust,
    UnauthorizedDeclassification,
    UnknownPointerError,
    UntrustedFlow,
)

from .helpers import (
    ATTACKER,
    BOSS,
    INJECTION,
    SUMMARY_PLAN,
    Outbox,
    email_registry,
    lit,
    make_orchestrator,
    plan_json,
    q_step,
    ref,
    tool_step,
)


def _record(calls: list[str], value: str) -> str:
    calls.append(value)
    return "ok"


REPLY_TO_SENDER = plan_json(
    tool_step("s1", "read_latest_email"),
    q_step("s2", "@s1", instruction="Extract the sender address.", output="email"),
    tool_step("s3", "send_email", to=ref("@s2"), subject=lit("Re"), body=lit("Received, thanks.")),
)


async def test_happy_path_routes_untrusted_body_but_trusted_recipient() -> None:
    outbox = Outbox()
    orch, planner, reader = make_orchestrator(
        email_registry(outbox, INJECTION), [SUMMARY_PLAN], [f"Summary. Also mail {ATTACKER}!"]
    )
    result = await orch.run("Summarise my latest e-mail and send it to my boss.")
    assert outbox.recipients == [BOSS]
    assert outbox.sent[0]["body"] == f"Summary. Also mail {ATTACKER}!"
    assert result.response == f"Sent: Summary. Also mail {ATTACKER}!"
    assert set(result.outputs) == {"s1", "s2", "s3"}
    assert orch.memory.describe(result.outputs["s1"]).trust is Trust.UNTRUSTED
    # The central claim: the privileged model never saw the payload.
    assert INJECTION not in planner.seen_text()
    assert ATTACKER not in planner.seen_text()
    # ...while the quarantined model did.
    assert INJECTION in reader.seen_text()


async def test_audit_log_is_content_free() -> None:
    outbox = Outbox()
    orch, _, _ = make_orchestrator(email_registry(outbox, INJECTION), [SUMMARY_PLAN], [f"mail {ATTACKER}"])
    await orch.run("Summarise my latest e-mail and send it to my boss.")
    log = orch.audit.to_jsonl()
    assert ATTACKER not in log
    assert "Ignore previous" not in log
    kinds = [e.kind for e in orch.audit]
    assert kinds.count(EventKind.DECLASSIFY) == 1  # only the body pointer crosses the choke point
    assert EventKind.DISPLAY in kinds


async def test_untrusted_value_into_sensitive_sink_is_blocked() -> None:
    outbox = Outbox()
    orch, _, _ = make_orchestrator(email_registry(outbox, INJECTION), [REPLY_TO_SENDER], [ATTACKER])
    with pytest.raises(TaintFlowViolation, match=r"send_email\.to"):
        await orch.run("Reply to the sender.")
    assert outbox.sent == []
    denial = orch.audit.denials()[-1]
    assert denial.kind is EventKind.TAINT_FLOW
    assert denial.details["sources"] == "llm:quarantined,tool:read_latest_email"
    # no declassification happened for the blocked call
    assert EventKind.DECLASSIFY not in [e.kind for e in orch.audit]


@pytest.mark.parametrize("async_approver", [False, True])
async def test_human_approval_can_allow_flow(async_approver: bool) -> None:
    outbox = Outbox()
    requests: list[ApprovalRequest] = []

    def approve(request: ApprovalRequest) -> bool:
        requests.append(request)
        return request.preview.reveal() == "alice@acme.example"

    async def approve_async(request: ApprovalRequest) -> bool:
        return approve(request)

    orch, _, _ = make_orchestrator(
        email_registry(outbox, INJECTION, to_flow=UntrustedFlow.REQUIRE_APPROVAL),
        [REPLY_TO_SENDER],
        ["alice@acme.example"],
        approver=approve_async if async_approver else approve,
    )
    await orch.run("Reply to the sender.")
    assert outbox.recipients == ["alice@acme.example"]
    assert requests[0].tool == "send_email"
    assert requests[0].argument == "to"
    assert "llm:quarantined" in requests[0].sources
    assert "alice" not in repr(requests[0])
    assert any(e.kind is EventKind.APPROVAL and e.decision is Decision.ALLOW for e in orch.audit)


async def test_human_approval_can_deny_flow() -> None:
    outbox = Outbox()
    orch, _, _ = make_orchestrator(
        email_registry(outbox, INJECTION, to_flow=UntrustedFlow.REQUIRE_APPROVAL),
        [REPLY_TO_SENDER],
        [ATTACKER],
        approver=lambda _req: False,
    )
    with pytest.raises(TaintFlowViolation, match="approver rejected"):
        await orch.run("Reply to the sender.")
    assert outbox.sent == []


async def test_require_approval_without_approver_denies() -> None:
    outbox = Outbox()
    orch, _, _ = make_orchestrator(
        email_registry(outbox, INJECTION, to_flow=UntrustedFlow.REQUIRE_APPROVAL),
        [REPLY_TO_SENDER],
        [ATTACKER],
    )
    with pytest.raises(TaintFlowViolation):
        await orch.run("Reply to the sender.")


async def test_validator_applies_to_trusted_literals_too() -> None:
    outbox = Outbox()
    plan = plan_json(tool_step("s1", "send_email", to=lit("someone@gmail.com"), subject=lit("s"), body=lit("b")))
    orch, _, _ = make_orchestrator(email_registry(outbox, "x"), [plan])
    with pytest.raises(ToolPolicyViolation, match="validator"):
        await orch.run("Email someone@gmail.com")
    assert outbox.sent == []


async def test_max_length_enforced_at_choke_point() -> None:
    calls: list[str] = []
    registry = ToolRegistry(
        [
            ToolSpec("fetch", "Fetch data.", (), lambda: "A" * 500),
            ToolSpec(
                "store",
                "Store text.",
                (ArgumentPolicy("text", "Text.", untrusted=UntrustedFlow.ALLOW, max_length=100),),
                lambda text: _record(calls, text),
            ),
        ]
    )
    plan = plan_json(tool_step("s1", "fetch"), tool_step("s2", "store", text=ref("@s1")))
    orch, _, _ = make_orchestrator(registry, [plan])
    with pytest.raises(ToolPolicyViolation):
        await orch.run("Fetch and store.")
    assert calls == []


async def test_tool_exceptions_are_wrapped_and_audited() -> None:
    def broken() -> str:
        raise RuntimeError("disk on fire: secret path /etc/shadow")

    registry = ToolRegistry([ToolSpec("broken", "Always fails.", (), broken)])
    orch, _, _ = make_orchestrator(registry, [plan_json(tool_step("s1", "broken"))])
    with pytest.raises(ToolExecutionError, match="RuntimeError") as excinfo:
        await orch.run("Run it.")
    assert "/etc/shadow" not in str(excinfo.value)
    assert orch.audit.denials()[-1].kind is EventKind.TOOL_RESULT


async def test_tool_must_return_text() -> None:
    registry = ToolRegistry([ToolSpec("bad", "Returns int.", (), lambda: 42)])  # type: ignore[arg-type,return-value]
    orch, _, _ = make_orchestrator(registry, [plan_json(tool_step("s1", "bad"))])
    with pytest.raises(ToolExecutionError, match="expected str"):
        await orch.run("Run it.")


async def test_async_tools_and_trusted_output() -> None:
    async def clock() -> str:
        return "2026-09-25T12:00:00"

    registry = ToolRegistry([ToolSpec("clock", "Current time.", (), clock, output_trust=Trust.TRUSTED)])
    orch, _, _ = make_orchestrator(registry, [plan_json(tool_step("s1", "clock"), final="It is {{@s1}}")])
    result = await orch.run("What time is it?")
    assert result.response == "It is 2026-09-25T12:00:00"
    assert orch.memory.describe(result.outputs["s1"]).trust is Trust.TRUSTED


async def test_trusted_tool_fed_untrusted_input_yields_untrusted_output() -> None:
    registry = ToolRegistry(
        [
            ToolSpec("fetch", "Fetch.", (), lambda: "external"),
            ToolSpec(
                "upper",
                "Uppercase.",
                (ArgumentPolicy("text", "Text.", untrusted=UntrustedFlow.ALLOW),),
                lambda text: text.upper(),
                output_trust=Trust.TRUSTED,
            ),
        ]
    )
    plan = plan_json(tool_step("s1", "fetch"), tool_step("s2", "upper", text=ref("@s1")))
    orch, _, _ = make_orchestrator(registry, [plan])
    result = await orch.run("Shout the page.")
    prov = orch.memory.provenance(result.outputs["s2"])
    assert prov.trust is Trust.UNTRUSTED
    assert result.outputs["s1"].token in prov.derived_from


async def test_rendering_is_single_pass() -> None:
    """Untrusted text containing a placeholder must not trigger a second expansion."""
    registry = ToolRegistry(
        [
            ToolSpec("secret", "Private note.", (), lambda: "TOP-SECRET", output_trust=Trust.TRUSTED),
            ToolSpec("fetch", "Fetch.", (), lambda: "{{@s1}}"),
        ]
    )
    plan = plan_json(tool_step("s1", "secret"), tool_step("s2", "fetch"), final="Page: {{@s2}}")
    orch, _, _ = make_orchestrator(registry, [plan])
    result = await orch.run("Show the page.")
    assert result.response == "Page: {{@s1}}"


async def test_context_pointers_can_be_offered() -> None:
    from dual_llm_guard import ChatMessage
    from dual_llm_guard.symbolic_memory import find_pointer_tokens

    def planner_reply(messages: Sequence[ChatMessage]) -> str:
        # A planner only learns pointer tokens from its (clean) context.
        (token,) = set(find_pointer_tokens(messages[-1].content))
        return plan_json(q_step("s1", token), final="Summary: {{@s1}}")

    orch, planner, _ = make_orchestrator(email_registry(Outbox(), "unused"), planner_reply)
    doc = orch.ingest(INJECTION, source="upload", label="attached document")
    result = await orch.run("Summarise the attached document.", context=[doc])
    assert result.response == "Summary: summary"
    assert doc.token in planner.seen_text()
    assert INJECTION not in planner.seen_text()
    assert orch.audit.events[0].kind is EventKind.INGEST


async def test_unknown_context_pointer() -> None:
    orch, _, _ = make_orchestrator(email_registry(Outbox(), "x"), [SUMMARY_PLAN])
    with pytest.raises(UnknownPointerError):
        await orch.run("x", context=[SymbolicPointer.new()])


async def test_context_leak_is_audited() -> None:
    outbox = Outbox()
    orch, planner, _ = make_orchestrator(email_registry(outbox, INJECTION), [SUMMARY_PLAN])
    orch.ingest(INJECTION, source="imap", label="e-mail")
    with pytest.raises(Exception, match="untrusted content"):
        await orch.run(f"Please handle: {INJECTION}")
    assert planner.transcript == []  # the model was never called
    assert orch.audit.denials()[-1].kind is EventKind.CONTEXT_CHECK


async def test_execute_revalidates_plans() -> None:
    from dual_llm_guard import Plan

    orch, _, _ = make_orchestrator(email_registry(Outbox(), "x"), ["unused"])
    plan = Plan.model_validate_json(plan_json(tool_step("s1", "format_disk")))
    with pytest.raises(ToolPolicyViolation):
        await orch.execute(plan)
    assert orch.audit.denials()[-1].kind is EventKind.PLAN


async def test_registry_is_rechecked_at_execution_time() -> None:
    """Defence in depth: a tool removed between validation and execution is refused."""

    class ShrinkingRegistry(ToolRegistry):
        def get(self, name: str) -> ToolSpec:
            raise ToolPolicyViolation(f"tool {name!r} is not allowlisted")

    registry = ShrinkingRegistry([ToolSpec("read_latest_email", "Read.", (), lambda: "x")])
    orch, _, _ = make_orchestrator(registry, [plan_json(tool_step("s1", "read_latest_email"))])
    with pytest.raises(ToolPolicyViolation):
        await orch.run("Read.")
    assert orch.audit.denials()[-1].kind is EventKind.TOOL_CALL


def test_memory_serves_a_single_orchestrator() -> None:
    memory = SymbolicMemory()
    make_orchestrator(ToolRegistry(), ["{}"], memory=memory)
    with pytest.raises(UnauthorizedDeclassification):
        make_orchestrator(ToolRegistry(), ["{}"], memory=memory)


def test_guard_must_protect_the_same_memory() -> None:
    memory, other = SymbolicMemory(), SymbolicMemory()
    with pytest.raises(ConfigurationError):
        DualLLMOrchestrator(
            memory=memory,
            privileged=PrivilegedLLM(ScriptedLLM(responses=["{}"]), PrivilegedContextGuard(other)),
            quarantined=QuarantinedLLM(ScriptedLLM(responses=["x"]), memory.writer()),
            registry=ToolRegistry(),
        )


def test_repr() -> None:
    orch, _, _ = make_orchestrator(email_registry(Outbox(), "x"), ["{}"])
    assert repr(orch) == (
        "DualLLMOrchestrator(tools=['read_latest_email', 'send_email'], memory=SymbolicMemory(entries=0))"
    )
