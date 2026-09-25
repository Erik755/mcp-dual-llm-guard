"""LLM backends: the protocol, a deterministic test double and an HTTP adapter."""

from .base import ChatMessage, LLMClient, Role
from .scripted import ScriptedLLM

__all__ = ["ChatMessage", "LLMClient", "Role", "ScriptedLLM"]
