"""Reference monitor with the declassification choke point.

:class:`DualLLMOrchestrator` is the Controller of the Dual LLM pattern: ordinary,
deterministic software (not a model) that mediates every interaction between
the planner, the quarantined model, the tools and the symbolic memory. It is the
**only** holder of the memory's :class:`~dual_llm_guard.symbolic_memory.DeclassificationCapability`.

Execution of a plan, step by step::

    plan (pointers only) ──► validate ──► for each step:
        quarantine step ──► resolve inputs for the Q-LLM ──► new tainted pointer
        tool step       ──► allowlist ──► taint-flow policy (on labels, no data read)
                           ──► human approval if required
                           ──► DECLASSIFICATION CHOKE POINT:
                                 resolve pointers → validate values → call tool
                           ──► store tool output as a new (tainted) pointer
    final response ──► resolve {{placeholders}} for display to the *user*

Policy decisions are taken on **labels** before any value is resolved; values
are resolved at the last possible moment, inside :meth:`DualLLMOrchestrator._invoke`,
into a local dictionary that is passed straight to the tool function and then
discarded. Resolved values are never logged, stored, or returned to a model.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from .audit import AuditLog, Decision, EventKind
from .exceptions import (
    ConfigurationError,
    SecurityViolation,
    TaintFlowViolation,
    ToolExecutionError,
    ToolPolicyViolation,
)
from .llm.base import LLMClient
from .policy import ApprovalRequest, Approver, ToolRegistry, ToolSpec, UntrustedFlow
from .privileged_llm import (
    LiteralArg,
    Plan,
    PrivilegedContextGuard,
    PrivilegedLLM,
    QuarantineStep,
    ToolCallStep,
    render_template,
    template_refs,
    validate_plan,
)
from .quarantined_llm import QuarantinedLLM, QuarantineInput
from .symbolic_memory import Purpose, Redacted, SymbolicMemory, SymbolicPointer
from .taint import Provenance, Trust

__all__ = ["DualLLMOrchestrator", "RunResult"]

_PLANNER_SOURCE = "llm:privileged"


@dataclass(frozen=True, slots=True)
class RunResult:
    """Outcome of a successful run.

    Attributes:
        plan: The validated plan that was executed.
        outputs: Pointer produced by each step, keyed by step id.
        response: Final answer rendered for the human user. It may contain
            untrusted text (e.g. a quarantined summary) -- it is meant for display,
            never to be fed back to the privileged planner.
    """

    plan: Plan
    outputs: Mapping[str, SymbolicPointer]
    response: str


@dataclass(frozen=True, slots=True)
class _Binding:
    """An argument bound either to a planner literal or to a pointer."""

    name: str
    provenance: Provenance
    pointer: SymbolicPointer | None = None
    literal: str = ""


@dataclass
class _RunState:
    offered: frozenset[str]
    outputs: dict[str, SymbolicPointer] = field(default_factory=dict)


class DualLLMOrchestrator:
    """Reference monitor mediating planner, quarantined model, tools and memory.

    Args:
        memory: The symbolic memory. Its capability is minted here, so a memory
            can serve exactly one orchestrator.
        privileged: The planner; its guard must protect the same memory.
        quarantined: The tool-less model.
        registry: Allowlisted tools and their argument policies.
        approver: Optional human-in-the-loop callback for
            :attr:`~dual_llm_guard.policy.UntrustedFlow.REQUIRE_APPROVAL` arguments.
        audit: Audit log (a new one is created if omitted).
    """

    def __init__(
        self,
        *,
        memory: SymbolicMemory,
        privileged: PrivilegedLLM,
        quarantined: QuarantinedLLM,
        registry: ToolRegistry,
        approver: Approver | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        if privileged.guard.memory is not memory:
            raise ConfigurationError("the planner's context guard must protect the same memory")
        self._memory = memory
        self._capability = memory.mint_capability("reference-monitor")
        self._privileged = privileged
        self._quarantined = quarantined
        self._registry = registry
        self._approver = approver
        self.audit = audit if audit is not None else AuditLog()

    @classmethod
    def create(
        cls,
        *,
        privileged_client: LLMClient,
        quarantined_client: LLMClient,
        registry: ToolRegistry,
        memory: SymbolicMemory | None = None,
        approver: Approver | None = None,
    ) -> DualLLMOrchestrator:
        """Wire every component correctly from two LLM clients."""
        memory = memory if memory is not None else SymbolicMemory()
        return cls(
            memory=memory,
            privileged=PrivilegedLLM(privileged_client, PrivilegedContextGuard(memory)),
            quarantined=QuarantinedLLM(quarantined_client, memory.writer()),
            registry=registry,
            approver=approver,
        )

    @property
    def memory(self) -> SymbolicMemory:
        """The symbolic memory mediated by this monitor."""
        return self._memory

    def __repr__(self) -> str:
        return f"DualLLMOrchestrator(tools={sorted(self._registry.names())}, memory={self._memory!r})"

    # ----------------------------------------------------------------- ingest
    def ingest(self, value: str, *, source: str, label: str) -> SymbolicPointer:
        """Store externally obtained data as untrusted and return its pointer."""
        pointer = self._memory.store(value, Provenance.untrusted(source), label=label)
        self.audit.record(
            EventKind.INGEST, Decision.ALLOW, "untrusted data stored", pointer=pointer.token, source=source
        )
        return pointer

    # -------------------------------------------------------------------- run
    async def run(self, user_request: str, *, context: Sequence[SymbolicPointer] = ()) -> RunResult:
        """Plan and execute ``user_request``.

        Args:
            user_request: The authenticated user's instruction (trusted input).
            context: Pointers the planner may reference (e.g. an attached document).

        Raises:
            SecurityViolation: Any policy violation; the run is aborted and audited.
            PlanValidationError: The planner produced an invalid plan.
        """
        pointers = [self._memory.describe(p) for p in context]
        try:
            plan = await self._privileged.plan(user_request, self._registry.catalog(), pointers)
        except SecurityViolation as exc:
            self.audit.record(EventKind.CONTEXT_CHECK, Decision.DENY, str(exc))
            raise
        self.audit.record(EventKind.CONTEXT_CHECK, Decision.ALLOW, "planner context clean")
        return await self.execute(plan, offered=[p.token for p in context])

    async def execute(self, plan: Plan, *, offered: Sequence[str] = ()) -> RunResult:
        """Validate and execute an already produced plan.

        Exposed separately so that plans can be reviewed, cached or produced by
        other means; validation is always re-applied.
        """
        state = _RunState(offered=frozenset(offered))
        try:
            validate_plan(plan, self._registry.catalog(), state.offered, self._memory)
        except Exception as exc:
            self.audit.record(EventKind.PLAN, Decision.DENY, str(exc))
            raise
        self.audit.record(EventKind.PLAN, Decision.ALLOW, f"plan with {len(plan.steps)} steps accepted")
        for step in plan.steps:
            if isinstance(step, QuarantineStep):
                state.outputs[step.id] = await self._run_quarantine(step, state)
            else:
                state.outputs[step.id] = await self._run_tool(step, state)
        response = self._render(plan.final_response, state)
        return RunResult(plan=plan, outputs=MappingProxyType(dict(state.outputs)), response=response)

    # ------------------------------------------------------------ quarantine
    async def _run_quarantine(self, step: QuarantineStep, state: _RunState) -> SymbolicPointer:
        inputs: list[QuarantineInput] = []
        for ref in step.inputs:
            pointer = self._deref(ref.ref, state)
            text = self._memory.resolve(pointer, self._capability, Purpose.QUARANTINED_INPUT)
            inputs.append(QuarantineInput(pointer, Redacted(text), self._memory.provenance(pointer)))
            self.audit.record(
                EventKind.QUARANTINE_READ,
                Decision.ALLOW,
                "input resolved for quarantined LLM",
                step=step.id,
                pointer=pointer.token,
            )
        output = await self._quarantined.process(
            step.instruction, inputs, output_kind=step.output, label=f"output of step {step.id}"
        )
        self.audit.record(
            EventKind.QUARANTINE_OUTPUT,
            Decision.ALLOW,
            "quarantined output stored as untrusted",
            step=step.id,
            pointer=output.token,
        )
        return output

    # ------------------------------------------------------------------ tools
    async def _run_tool(self, step: ToolCallStep, state: _RunState) -> SymbolicPointer:
        try:
            tool = self._registry.get(step.tool)
        except ToolPolicyViolation as exc:
            self.audit.record(EventKind.TOOL_CALL, Decision.DENY, str(exc), step=step.id)
            raise
        bindings: list[_Binding] = []
        for name, value in step.args.items():
            policy = tool.argument(name)
            if isinstance(value, LiteralArg):
                binding = _Binding(name, Provenance.trusted(_PLANNER_SOURCE), literal=value.literal)
            else:
                pointer = self._deref(value.ref, state)
                binding = _Binding(name, self._memory.provenance(pointer), pointer=pointer)
            # Taint-flow decision on the *label*; nothing has been resolved yet.
            if binding.provenance.is_untrusted:
                await self._enforce_untrusted_flow(tool, step.id, binding, policy.untrusted)
            bindings.append(binding)
        return await self._invoke(tool, step.id, bindings)

    async def _enforce_untrusted_flow(
        self, tool: ToolSpec, step_id: str, binding: _Binding, flow: UntrustedFlow
    ) -> None:
        sources = ",".join(sorted(binding.provenance.sources))
        where = f"{tool.name}.{binding.name}"
        if flow is UntrustedFlow.ALLOW:
            self.audit.record(
                EventKind.TAINT_FLOW,
                Decision.ALLOW,
                f"untrusted data allowed into {where}",
                step=step_id,
                sources=sources,
            )
            return
        # Untrusted values always come from pointers; the pointer check keeps mypy honest.
        if flow is UntrustedFlow.REQUIRE_APPROVAL and self._approver is not None and binding.pointer is not None:
            preview = self._memory.resolve(binding.pointer, self._capability, Purpose.USER_DISPLAY)
            request = ApprovalRequest(
                tool.name, binding.name, binding.pointer, binding.provenance.sources, Redacted(preview)
            )
            verdict = self._approver(request)
            approved = await verdict if inspect.isawaitable(verdict) else verdict
            decision = Decision.ALLOW if approved else Decision.DENY
            self.audit.record(
                EventKind.APPROVAL,
                decision,
                f"human approval for untrusted data into {where}",
                step=step_id,
                pointer=binding.pointer.token,
            )
            if approved:
                return
            raise TaintFlowViolation(f"human approver rejected untrusted data into {where}")
        self.audit.record(
            EventKind.TAINT_FLOW,
            Decision.DENY,
            f"untrusted data blocked from sink {where}",
            step=step_id,
            sources=sources,
        )
        raise TaintFlowViolation(f"untrusted data (sources: {sources}) cannot flow into sensitive sink {where}")

    async def _invoke(self, tool: ToolSpec, step_id: str, bindings: Sequence[_Binding]) -> SymbolicPointer:
        """The declassification choke point.

        This is the only place where pointers bound to tool arguments are turned
        back into text, immediately before the call. The resolved values live
        only in the local ``kwargs`` dictionary.
        """
        kwargs: dict[str, str] = {}
        for binding in bindings:
            if binding.pointer is not None:
                value = self._memory.resolve(binding.pointer, self._capability, Purpose.TOOL_ARGUMENT)
                self.audit.record(
                    EventKind.DECLASSIFY,
                    Decision.ALLOW,
                    f"resolved at choke point for {tool.name}.{binding.name}",
                    step=step_id,
                    pointer=binding.pointer.token,
                )
            else:
                value = binding.literal
            policy = tool.argument(binding.name)
            if len(value) > policy.max_length or (policy.validator is not None and not policy.validator(value)):
                self.audit.record(
                    EventKind.TOOL_CALL,
                    Decision.DENY,
                    f"argument {tool.name}.{binding.name} failed validation",
                    step=step_id,
                )
                raise ToolPolicyViolation(f"argument {tool.name}.{binding.name} failed its policy validator")
            kwargs[binding.name] = value
        self.audit.record(EventKind.TOOL_CALL, Decision.ALLOW, f"calling {tool.name}", step=step_id)
        try:
            result = tool.function(**kwargs)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            self.audit.record(
                EventKind.TOOL_RESULT, Decision.DENY, f"{tool.name} raised {type(exc).__name__}", step=step_id
            )
            raise ToolExecutionError(f"tool {tool.name!r} failed: {type(exc).__name__}") from exc
        finally:
            kwargs.clear()  # drop resolved values as soon as the call returns
        if not isinstance(result, str):
            raise ToolExecutionError(f"tool {tool.name!r} returned {type(result).__name__}, expected str")
        base = Provenance(tool.output_trust, frozenset({f"tool:{tool.name}"}))
        provenance = base.join(b.provenance for b in bindings).with_lineage(
            b.pointer.token for b in bindings if b.pointer is not None
        )
        if tool.output_trust is Trust.UNTRUSTED:
            provenance = Provenance(Trust.UNTRUSTED, provenance.sources, provenance.derived_from)
        pointer = self._memory.store(result, provenance, label=f"output of step {step_id} ({tool.name})")
        self.audit.record(
            EventKind.TOOL_RESULT,
            Decision.ALLOW,
            f"{tool.name} output stored as {provenance.trust.value}",
            step=step_id,
            pointer=pointer.token,
        )
        return pointer

    # ---------------------------------------------------------------- helpers
    def _deref(self, ref: str, state: _RunState) -> SymbolicPointer:
        if ref.startswith("@"):
            return state.outputs[ref[1:]]
        return SymbolicPointer(ref)

    def _render(self, template: str, state: _RunState) -> str:
        """Resolve ``{{ref}}`` placeholders for display to the human user."""
        values: dict[str, str] = {}
        for ref in dict.fromkeys(template_refs(template)):
            pointer = self._deref(ref, state)
            values[ref] = self._memory.resolve(pointer, self._capability, Purpose.USER_DISPLAY)
            self.audit.record(EventKind.DISPLAY, Decision.ALLOW, "resolved for user display", pointer=pointer.token)
        return render_template(template, values)
