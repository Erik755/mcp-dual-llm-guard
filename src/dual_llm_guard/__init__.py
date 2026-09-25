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

from .audit import AuditEvent, AuditLog, Decision, EventKind
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
from .mcp_adapter import MCPImportReport, MCPToolPolicy, register_mcp_tools
from .orchestrator import DualLLMOrchestrator, RunResult
from .policy import (
    ApprovalRequest,
    ArgumentPolicy,
    ToolRegistry,
    ToolSpec,
    UntrustedFlow,
    email_domain_allowlist,
    matches_regex,
)
from .privileged_llm import Plan, PrivilegedContextGuard, PrivilegedLLM
from .quarantined_llm import QuarantinedLLM
from .symbolic_memory import PointerMetadata, Purpose, Redacted, SymbolicMemory, SymbolicPointer
from .taint import Provenance, Trust
from .tool_manifest import ManifestPinStore, PoisoningScanner, ToolManifest

__version__ = "0.1.0"

__all__ = [
    "ApprovalRequest",
    "ArgumentPolicy",
    "AuditEvent",
    "AuditLog",
    "ChatMessage",
    "ConfigurationError",
    "Decision",
    "DualLLMGuardError",
    "DualLLMOrchestrator",
    "EventKind",
    "LLMBackendError",
    "LLMClient",
    "MCPImportReport",
    "MCPToolPolicy",
    "ManifestPinStore",
    "Plan",
    "PlanValidationError",
    "PointerMetadata",
    "PoisoningScanner",
    "PrivilegedContextGuard",
    "PrivilegedLLM",
    "Provenance",
    "Purpose",
    "QuarantineBreach",
    "QuarantineOutputError",
    "QuarantinedLLM",
    "Redacted",
    "RunResult",
    "ScriptedLLM",
    "SecurityViolation",
    "SymbolicMemory",
    "SymbolicPointer",
    "TaintFlowViolation",
    "ToolExecutionError",
    "ToolManifest",
    "ToolManifestChanged",
    "ToolPoisoningDetected",
    "ToolPolicyViolation",
    "ToolRegistry",
    "ToolSpec",
    "Trust",
    "UnauthorizedDeclassification",
    "UnknownPointerError",
    "UnpinnedToolError",
    "UntrustedContentInPrivilegedContext",
    "UntrustedFlow",
    "__version__",
    "email_domain_allowlist",
    "matches_regex",
    "register_mcp_tools",
]
