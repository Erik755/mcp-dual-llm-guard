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

__version__ = "0.1.0"

__all__ = [
    "__version__",
]
