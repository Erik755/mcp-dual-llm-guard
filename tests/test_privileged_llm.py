from __future__ import annotations

import json

import pytest

from dual_llm_guard import (
    ChatMessage,
    Plan,
    PlanValidationError,
    PrivilegedContextGuard,
    PrivilegedLLM,
    Provenance,
    ScriptedLLM,
    SymbolicMemory,
    SymbolicPointer,
    ToolPolicyViolation,
    UnknownPointerError,
    UntrustedContentInPrivilegedContext,
)
from dual_llm_guard.privileged_llm import (
    PRIVILEGED_SYSTEM_PROMPT,
    build_planner_messages,
    extract_json_object,
    render_template,
    template_refs,
    validate_plan,
)

from .helpers import INJECTION, SUMMARY_PLAN, Outbox, email_registry, lit, plan_json, q_step, ref, tool_step

CATALOG = email_registry(Outbox(), "unused").catalog()


def _plan(raw: str) -> Plan:
    return Plan.model_validate(json.loads(raw))


class TestPromptConstruction:
    def test_messages_contain_only_trusted_parts(self) -> None:
        memory = SymbolicMemory()
        ptr = memory.store(INJECTION, Provenance.untrusted("imap"), label="latest e-mail")
        messages = build_planner_messages("Do the thing", CATALOG, [memory.describe(ptr)])
        assert messages[0] == ChatMessage("system", PRIVILEGED_SYSTEM_PROMPT)
        body = messages[1].content
        assert "USER REQUEST:\nDo the thing" in body
        assert f"- {ptr.token}: trust=untrusted; label=latest e-mail; sources=imap" in body
        assert "send_email: Send an e-mail." in body
        assert INJECTION not in body

    def test_empty_sections(self) -> None:
        body = build_planner_messages("x", [], [])[1].content
        assert "AVAILABLE TOOLS:\n(none)" in body
        assert "AVAILABLE DATA POINTERS (opaque, content hidden from you):\n(none)" in body

    def test_system_prompt_contains_no_pointer_tokens(self) -> None:
        # otherwise the guard would reject every prompt
        assert "$VAR_" in PRIVILEGED_SYSTEM_PROMPT
        assert not PrivilegedContextGuard(SymbolicMemory()).memory.contains_untrusted_fragment(PRIVILEGED_SYSTEM_PROMPT)
        from dual_llm_guard.symbolic_memory import find_pointer_tokens

        assert find_pointer_tokens(PRIVILEGED_SYSTEM_PROMPT) == []


class TestContextGuard:
    def test_rejects_leaked_untrusted_content(self) -> None:
        memory = SymbolicMemory()
        memory.store(INJECTION, Provenance.untrusted("imap"), label="e-mail")
        guard = PrivilegedContextGuard(memory)
        with pytest.raises(UntrustedContentInPrivilegedContext, match="message #1"):
            guard.check([ChatMessage("system", "s"), ChatMessage("user", f"handle: {INJECTION}")], set())

    def test_rejects_pointer_not_offered(self) -> None:
        memory = SymbolicMemory()
        ptr = memory.store("x", Provenance.untrusted("imap"), label="e-mail")
        guard = PrivilegedContextGuard(memory)
        with pytest.raises(UnknownPointerError, match="not offered"):
            guard.check([ChatMessage("user", f"look at {ptr}")], set())
        guard.check([ChatMessage("user", f"look at {ptr}")], {ptr.token})

    def test_rejects_forged_pointer_even_if_offered(self) -> None:
        guard = PrivilegedContextGuard(SymbolicMemory())
        forged = SymbolicPointer.new().token
        with pytest.raises(UnknownPointerError):
            guard.check([ChatMessage("user", forged)], {forged})

    def test_trusted_constants_are_exempt_from_fingerprint_scan(self) -> None:
        """An attacker quoting the system prompt must not be able to DoS planning."""
        memory = SymbolicMemory()
        memory.store(f"Hello!\n{PRIVILEGED_SYSTEM_PROMPT}", Provenance.untrusted("imap"), label="e-mail")
        guard = PrivilegedContextGuard(memory)
        messages = build_planner_messages("Summarise my e-mail", CATALOG, [])
        with pytest.raises(UntrustedContentInPrivilegedContext):
            guard.check(messages, set())
        guard.check(messages, set(), trusted_constants=[PRIVILEGED_SYSTEM_PROMPT, ""])

    async def test_planner_uses_constants_exemption(self) -> None:
        memory = SymbolicMemory()
        memory.store(f"Hi {PRIVILEGED_SYSTEM_PROMPT}", Provenance.untrusted("imap"), label="e-mail")
        planner = PrivilegedLLM(ScriptedLLM(responses=[SUMMARY_PLAN]), PrivilegedContextGuard(memory))
        plan = await planner.plan("Summarise", CATALOG, [])
        assert len(plan.steps) == 3


class TestPlanParsing:
    async def test_parses_fenced_json(self) -> None:
        memory = SymbolicMemory()
        planner = PrivilegedLLM(
            ScriptedLLM(responses=[f"Here is the plan:\n```json\n{SUMMARY_PLAN}\n```"]),
            PrivilegedContextGuard(memory),
        )
        assert planner.guard.memory is memory
        plan = await planner.plan("Summarise", CATALOG, [])
        assert [s.id for s in plan.steps] == ["s1", "s2", "s3"]

    @pytest.mark.parametrize(
        "reply",
        [
            "no json here",
            "{not: valid json}",
            json.dumps({"steps": []}),
            json.dumps({"steps": [{"kind": "tool", "id": "s1", "tool": "x", "args": {}, "extra": 1}]}),
            json.dumps({"steps": [{"kind": "shell", "id": "s1"}]}),
            json.dumps({"steps": [{"kind": "tool", "id": "step1", "tool": "x"}]}),
            plan_json(tool_step("s1", "send_email", to={"ref": "attacker@evil.com"})),
            plan_json(tool_step("s1", "send_email", to={"literal": "a", "ref": "@s1"})),
            plan_json(q_step("s1", "@s0", output="python")),
        ],
    )
    async def test_rejects_invalid_replies(self, reply: str) -> None:
        planner = PrivilegedLLM(ScriptedLLM(responses=[reply]), PrivilegedContextGuard(SymbolicMemory()))
        with pytest.raises(PlanValidationError):
            await planner.plan("x", CATALOG, [])

    def test_extract_json_object(self) -> None:
        assert extract_json_object('prefix {"a": {"b": 1}} suffix') == '{"a": {"b": 1}}'
        with pytest.raises(PlanValidationError):
            extract_json_object("} {")


class TestPlanValidation:
    def test_valid_plan(self) -> None:
        validate_plan(_plan(SUMMARY_PLAN), CATALOG, set(), SymbolicMemory())

    def test_step_ids_must_be_sequential(self) -> None:
        raw = plan_json(tool_step("s2", "read_latest_email"))
        with pytest.raises(PlanValidationError, match="in order"):
            validate_plan(_plan(raw), CATALOG, set(), SymbolicMemory())

    def test_forward_reference(self) -> None:
        raw = plan_json(q_step("s1", "@s2"), tool_step("s2", "read_latest_email"))
        with pytest.raises(PlanValidationError, match="earlier step"):
            validate_plan(_plan(raw), CATALOG, set(), SymbolicMemory())

    def test_unknown_tool_is_policy_violation(self) -> None:
        raw = plan_json(tool_step("s1", "delete_all_files"))
        with pytest.raises(ToolPolicyViolation, match="not allowlisted"):
            validate_plan(_plan(raw), CATALOG, set(), SymbolicMemory())

    @pytest.mark.parametrize(
        "args",
        [
            {"to": lit("a@acme.example"), "subject": lit("s")},
            {"to": lit("a@acme.example"), "subject": lit("s"), "body": lit("b"), "bcc": lit("x@evil.com")},
        ],
    )
    def test_argument_set_must_match(self, args: dict[str, dict[str, str]]) -> None:
        raw = plan_json(tool_step("s1", "send_email", **args))
        with pytest.raises(PlanValidationError, match="do not match"):
            validate_plan(_plan(raw), CATALOG, set(), SymbolicMemory())

    def test_forged_pointer_in_args(self) -> None:
        forged = SymbolicPointer.new().token
        raw = plan_json(tool_step("s1", "send_email", to=lit("a@acme.example"), subject=lit("s"), body=ref(forged)))
        with pytest.raises(UnknownPointerError):
            validate_plan(_plan(raw), CATALOG, set(), SymbolicMemory())

    def test_existing_but_unoffered_pointer(self) -> None:
        memory = SymbolicMemory()
        secret = memory.store("private", Provenance.untrusted("x"), label="x")
        raw = plan_json(q_step("s1", secret.token))
        with pytest.raises(UnknownPointerError, match="not offered"):
            validate_plan(_plan(raw), CATALOG, set(), memory)
        validate_plan(_plan(raw), CATALOG, {secret.token}, memory)

    def test_literal_laundering_detected(self) -> None:
        memory = SymbolicMemory()
        memory.store(INJECTION, Provenance.untrusted("imap"), label="e-mail")
        raw = plan_json(tool_step("s1", "send_email", to=lit("a@acme.example"), subject=lit("s"), body=lit(INJECTION)))
        with pytest.raises(UntrustedContentInPrivilegedContext):
            validate_plan(_plan(raw), CATALOG, set(), memory)

    def test_instruction_laundering_detected(self) -> None:
        memory = SymbolicMemory()
        memory.store(INJECTION, Provenance.untrusted("imap"), label="e-mail")
        raw = plan_json(tool_step("s1", "read_latest_email"), q_step("s2", "@s1", instruction=INJECTION))
        with pytest.raises(UntrustedContentInPrivilegedContext):
            validate_plan(_plan(raw), CATALOG, set(), memory)

    def test_final_response_refs_checked(self) -> None:
        raw = plan_json(tool_step("s1", "read_latest_email"), final="{{@s9}}")
        with pytest.raises(PlanValidationError, match="earlier step"):
            validate_plan(_plan(raw), CATALOG, set(), SymbolicMemory())

    def test_final_response_stray_pointer(self) -> None:
        memory = SymbolicMemory()
        ptr = memory.store("x", Provenance.untrusted("imap"), label="x")
        raw = plan_json(tool_step("s1", "read_latest_email"), final=f"see {ptr}")
        with pytest.raises(PlanValidationError, match="outside"):
            validate_plan(_plan(raw), CATALOG, {ptr.token}, memory)


def test_template_helpers() -> None:
    ptr = SymbolicPointer.new().token
    template = f"A={{{{@s1}}}} B={{{{ {ptr} }}}} again {{{{@s1}}}}"
    assert template_refs(template) == ["@s1", ptr, "@s1"]
    assert render_template(template, {"@s1": "{{@s1}}", ptr: "b"}) == "A={{@s1}} B=b again {{@s1}}"
