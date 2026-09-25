"""Deterministic LLM double for tests, demos and offline evaluation."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..exceptions import LLMBackendError
from .base import ChatMessage

__all__ = ["ScriptedLLM"]

Responder = Callable[[Sequence[ChatMessage]], str]


@dataclass
class ScriptedLLM:
    """An :class:`~dual_llm_guard.llm.base.LLMClient` whose replies are scripted.

    It either replays a fixed queue of responses or delegates to a pure
    function of the conversation. Every conversation it receives is recorded
    in :attr:`transcript`, which lets tests prove *what a model saw* -- the
    central claim of the Dual LLM pattern is about model inputs, so this is
    the property worth asserting.

    Args:
        responses: Replies returned in order, one per call.
        responder: Alternatively, a function computing the reply from the messages.
        name: Label used in error messages.
    """

    responses: Sequence[str] = ()
    responder: Responder | None = None
    name: str = "scripted"
    transcript: list[tuple[ChatMessage, ...]] = field(default_factory=list, init=False)
    _cursor: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if bool(self.responses) == (self.responder is not None):
            raise ValueError("provide exactly one of 'responses' or 'responder'")

    async def complete(self, messages: Sequence[ChatMessage]) -> str:
        """Record the conversation and return the next scripted reply."""
        self.transcript.append(tuple(messages))
        if self.responder is not None:
            return self.responder(messages)
        if self._cursor >= len(self.responses):
            raise LLMBackendError(f"{self.name}: script exhausted after {self._cursor} calls")
        reply = self.responses[self._cursor]
        self._cursor += 1
        return reply

    def seen_text(self) -> str:
        """Concatenate every message this model ever received (for assertions)."""
        return "\n".join(m.content for conv in self.transcript for m in conv)
