"""Adapter for OpenAI-compatible ``/chat/completions`` endpoints.

Works with any server implementing the de-facto OpenAI Chat Completions wire
format (OpenAI, Azure OpenAI with a compatible gateway, vLLM, Ollama, LM Studio,
llama.cpp server, OpenRouter, ...). Requires the optional ``httpx`` dependency::

    pip install "mcp-dual-llm-guard[openai]"

The API key is read from an environment variable at construction time and is
never included in ``repr`` output or exception messages.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from ..exceptions import ConfigurationError, LLMBackendError
from .base import ChatMessage

if TYPE_CHECKING:  # pragma: no cover
    import httpx

__all__ = ["OpenAICompatibleLLM"]


class OpenAICompatibleLLM:
    """Async client for an OpenAI-compatible chat completion API.

    Args:
        model: Model identifier understood by the server.
        base_url: API root, e.g. ``https://api.openai.com/v1`` or ``http://localhost:11434/v1``.
        api_key_env: Name of the environment variable holding the key. If the
            variable is unset and ``require_api_key`` is true, construction fails.
        require_api_key: Set to ``False`` for local servers that need no key.
        temperature: Sampling temperature (``0`` recommended for planners).
        timeout: Request timeout in seconds.
        json_mode: Ask the server for a JSON object response (``response_format``).
        transport: Optional custom ``httpx`` transport (used by the test-suite).
    """

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "https://api.openai.com/v1",
        api_key_env: str = "OPENAI_API_KEY",
        require_api_key: bool = True,
        temperature: float = 0.0,
        timeout: float = 60.0,
        json_mode: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            import httpx  # noqa: PLC0415 - optional dependency
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ConfigurationError(
                "OpenAICompatibleLLM requires httpx: pip install 'mcp-dual-llm-guard[openai]'"
            ) from exc
        key = os.environ.get(api_key_env)
        if require_api_key and not key:
            raise ConfigurationError(f"environment variable {api_key_env} is not set")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        self._model = model
        self._temperature = temperature
        self._json_mode = json_mode
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    def __repr__(self) -> str:
        return f"OpenAICompatibleLLM(model={self._model!r})"

    async def complete(self, messages: Sequence[ChatMessage]) -> str:
        """Send ``messages`` and return the first choice's content."""
        import httpx  # noqa: PLC0415 - optional dependency

        payload: dict[str, Any] = {
            "model": self._model,
            "temperature": self._temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}
        try:
            response = await self._client.post("/chat/completions", json=payload)
            response.raise_for_status()
            data: Any = response.json()
        except httpx.HTTPStatusError as exc:
            raise LLMBackendError(f"LLM endpoint returned HTTP {exc.response.status_code}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise LLMBackendError(f"LLM request failed: {type(exc).__name__}") from exc
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMBackendError("malformed chat completion response") from exc
        if not isinstance(content, str):
            raise LLMBackendError("chat completion content is not a string")
        return content

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()
