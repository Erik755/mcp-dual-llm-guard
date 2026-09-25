"""Exception hierarchy for control-flow and data-flow violations.

Every security-relevant refusal raised by this package derives from
:class:`SecurityViolation`, so callers can apply a single, conservative
``except SecurityViolation`` policy (abort the task, alert, keep the audit
trail) while still being able to distinguish the precise failure mode.

Hierarchy::

    DualLLMGuardError
    ├── SecurityViolation
    │   ├── TaintFlowViolation
    │   ├── UnauthorizedDeclassification
    │   ├── UnknownPointerError
    │   ├── UntrustedContentInPrivilegedContext
    │   ├── QuarantineBreach
    │   ├── ToolPolicyViolation
    │   └── ToolPoisoningDetected
    │       ├── ToolManifestChanged
    │       └── UnpinnedToolError
    ├── PlanValidationError
    ├── QuarantineOutputError
    ├── ToolExecutionError
    ├── ConfigurationError
    └── LLMBackendError
"""

from __future__ import annotations

__all__ = [
    "ConfigurationError",
    "DualLLMGuardError",
    "LLMBackendError",
    "PlanValidationError",
    "QuarantineBreach",
    "QuarantineOutputError",
    "SecurityViolation",
    "TaintFlowViolation",
    "ToolExecutionError",
    "ToolManifestChanged",
    "ToolPoisoningDetected",
    "ToolPolicyViolation",
    "UnauthorizedDeclassification",
    "UnknownPointerError",
    "UnpinnedToolError",
    "UntrustedContentInPrivilegedContext",
]


class DualLLMGuardError(Exception):
    """Root of every exception raised by :mod:`dual_llm_guard`."""


class SecurityViolation(DualLLMGuardError):
    """A security invariant was about to be broken and the action was refused.

    Messages attached to these exceptions never contain untrusted content:
    they reference symbolic pointers, tool names and policy identifiers only,
    so they are safe to log and to surface to the privileged planner.
    """


class TaintFlowViolation(SecurityViolation):
    """Untrusted data attempted to flow into a sink that does not accept it.

    Example: an e-mail address extracted from an untrusted message being bound
    to the ``to`` argument of ``send_email``.
    """


class UnauthorizedDeclassification(SecurityViolation):
    """Someone other than the declassification choke point tried to resolve data."""


class UnknownPointerError(SecurityViolation):
    """A pointer that was never issued by this memory was presented.

    This is how pointer forgery and pointer enumeration attempts surface.
    """


class UntrustedContentInPrivilegedContext(SecurityViolation):
    """Raw untrusted content was detected in the privileged LLM's input."""


class QuarantineBreach(SecurityViolation):
    """An attempt was made to grant tools or capabilities to the quarantined LLM."""


class ToolPolicyViolation(SecurityViolation):
    """A tool call was not allowed by the operator policy (allowlist/argument rules)."""


class ToolPoisoningDetected(SecurityViolation):
    """An MCP tool manifest looks malicious or does not match its declared contract."""


class ToolManifestChanged(ToolPoisoningDetected):
    """A pinned MCP tool manifest changed after approval (a "rug pull")."""


class UnpinnedToolError(ToolPoisoningDetected):
    """An MCP tool was offered that the operator never reviewed and pinned."""


class PlanValidationError(DualLLMGuardError):
    """The privileged LLM produced a plan that is malformed or references unknown entities."""


class QuarantineOutputError(DualLLMGuardError):
    """The quarantined LLM's output did not match the output type requested by the plan."""


class ToolExecutionError(DualLLMGuardError):
    """A tool (local or remote MCP) failed while executing an authorised call."""


class ConfigurationError(DualLLMGuardError):
    """The guard was wired incorrectly by the integrating application."""


class LLMBackendError(DualLLMGuardError):
    """An LLM backend failed (transport error, malformed response, missing credentials)."""
