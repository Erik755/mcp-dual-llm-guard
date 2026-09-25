"""dual_llm_guard -- Dual LLM with Symbolic Memory for MCP agents.

A secure middleware implementing Simon Willison's *Dual LLM* pattern with
symbolic memory, a reference monitor and a declassification choke point, plus
tool-poisoning defences for Model Context Protocol ecosystems.

Quick tour::

    memory = SymbolicMemory()
    orchestrator = DualLLMOrchestrator.create(
        privileged_client=planner_llm,
        quarantined_client=reader_llm,
        registry=ToolRegistry([...]),
        memory=memory,
    )
    result = await orchestrator.run("Summarise my latest e-mail and send it to my boss")
"""

from .exceptions import (
    ConfigurationError,
    DualLLMGuardError,
    LLMBackendError,
    PlanValidationError,
    QuarantineBreach,
    QuarantineOutputError,
    SecurityViolation,
    TaintFlowViolation,
    ToolExecutionError,
    ToolManifestChanged,
    ToolPoisoningDetected,
    ToolPolicyViolation,
    UnauthorizedDeclassification,
    UnknownPointerError,
    UnpinnedToolError,
    UntrustedContentInPrivilegedContext,
)
from .llm import ChatMessage, LLMClient, ScriptedLLM
from .symbolic_memory import PointerMetadata, Purpose, Redacted, SymbolicMemory, SymbolicPointer
from .taint import Provenance, Trust

__version__ = "0.1.0"

__all__ = [
    "ChatMessage",
    "ConfigurationError",
    "DualLLMGuardError",
    "LLMBackendError",
    "LLMClient",
    "PlanValidationError",
    "PointerMetadata",
    "Provenance",
    "Purpose",
    "QuarantineBreach",
    "QuarantineOutputError",
    "Redacted",
    "ScriptedLLM",
    "SecurityViolation",
    "SymbolicMemory",
    "SymbolicPointer",
    "TaintFlowViolation",
    "ToolExecutionError",
    "ToolManifestChanged",
    "ToolPoisoningDetected",
    "ToolPolicyViolation",
    "Trust",
    "UnauthorizedDeclassification",
    "UnknownPointerError",
    "UnpinnedToolError",
    "UntrustedContentInPrivilegedContext",
    "__version__",
]
