"""Backend-agnostic LLM interface."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

__all__ = ["ChatMessage", "LLMClient", "Role"]

Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """A single chat turn sent to a model."""

    role: Role
    content: str


@runtime_checkable
class LLMClient(Protocol):
    """Minimal asynchronous chat-completion interface.

    The guard never relies on provider-specific features such as native tool
    calling: the privileged model returns a JSON plan that is validated by
    trusted code, and the quarantined model returns plain text. Keeping the
    interface this small makes every backend (hosted API, local model, test
    double) interchangeable and keeps tool access out of the model layer.
    """

    async def complete(self, messages: Sequence[ChatMessage]) -> str:
        """Return the assistant's reply to ``messages``."""
        ...
