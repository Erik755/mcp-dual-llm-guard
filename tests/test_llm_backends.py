from __future__ import annotations

import json

import httpx
import pytest

from dual_llm_guard import ChatMessage, ConfigurationError, LLMBackendError, LLMClient, ScriptedLLM
from dual_llm_guard.llm.openai_compat import OpenAICompatibleLLM

MESSAGES = [ChatMessage("system", "sys"), ChatMessage("user", "hi")]


class TestScriptedLLM:
    async def test_replays_responses_in_order(self) -> None:
        llm = ScriptedLLM(responses=["a", "b"])
        assert await llm.complete(MESSAGES) == "a"
        assert await llm.complete(MESSAGES) == "b"
        with pytest.raises(LLMBackendError, match="exhausted"):
            await llm.complete(MESSAGES)

    async def test_responder_and_transcript(self) -> None:
        llm = ScriptedLLM(responder=lambda msgs: msgs[-1].content.upper())
        assert await llm.complete(MESSAGES) == "HI"
        assert llm.transcript == [tuple(MESSAGES)]
        assert llm.seen_text() == "sys\nhi"

    def test_exactly_one_source_required(self) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            ScriptedLLM()
        with pytest.raises(ValueError, match="exactly one"):
            ScriptedLLM(responses=["a"], responder=lambda _m: "b")

    def test_satisfies_protocol(self) -> None:
        assert isinstance(ScriptedLLM(responses=["a"]), LLMClient)


def _llm(handler: httpx.MockTransport, monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> OpenAICompatibleLLM:
    monkeypatch.setenv("TEST_LLM_KEY", "sk-test-123")
    return OpenAICompatibleLLM(
        "test-model",
        base_url="https://llm.example/v1/",
        api_key_env="TEST_LLM_KEY",
        transport=handler,
        **kwargs,  # type: ignore[arg-type]
    )


class TestOpenAICompatibleLLM:
    async def test_request_shape_and_reply(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"choices": [{"message": {"content": "hello"}}]})

        llm = _llm(httpx.MockTransport(handler), monkeypatch, json_mode=True)
        assert await llm.complete(MESSAGES) == "hello"
        await llm.aclose()
        request = seen[0]
        assert str(request.url) == "https://llm.example/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer sk-test-123"
        body = json.loads(request.content)
        assert body["model"] == "test-model"
        assert body["temperature"] == 0.0
        assert body["response_format"] == {"type": "json_object"}
        assert body["messages"] == [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]

    async def test_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        llm = _llm(httpx.MockTransport(lambda _r: httpx.Response(429, json={})), monkeypatch)
        with pytest.raises(LLMBackendError, match="HTTP 429"):
            await llm.complete(MESSAGES)

    async def test_transport_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down", request=request)

        llm = _llm(httpx.MockTransport(boom), monkeypatch)
        with pytest.raises(LLMBackendError, match="ConnectError"):
            await llm.complete(MESSAGES)

    async def test_invalid_json_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        llm = _llm(httpx.MockTransport(lambda _r: httpx.Response(200, text="not json")), monkeypatch)
        with pytest.raises(LLMBackendError, match="request failed"):
            await llm.complete(MESSAGES)

    @pytest.mark.parametrize("payload", [{}, {"choices": []}, {"choices": [{"message": {}}]}, {"choices": "x"}])
    async def test_malformed_response(self, monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
        llm = _llm(httpx.MockTransport(lambda _r: httpx.Response(200, json=payload)), monkeypatch)
        with pytest.raises(LLMBackendError, match="malformed"):
            await llm.complete(MESSAGES)

    async def test_non_string_content(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {"choices": [{"message": {"content": None}}]}
        llm = _llm(httpx.MockTransport(lambda _r: httpx.Response(200, json=payload)), monkeypatch)
        with pytest.raises(LLMBackendError, match="not a string"):
            await llm.complete(MESSAGES)

    def test_missing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MISSING_KEY_VAR", raising=False)
        with pytest.raises(ConfigurationError, match="MISSING_KEY_VAR"):
            OpenAICompatibleLLM("m", api_key_env="MISSING_KEY_VAR")

    async def test_keyless_local_server(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MISSING_KEY_VAR", raising=False)
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        llm = OpenAICompatibleLLM(
            "m", api_key_env="MISSING_KEY_VAR", require_api_key=False, transport=httpx.MockTransport(handler)
        )
        assert await llm.complete(MESSAGES) == "ok"
        assert "Authorization" not in seen[0].headers
        assert "response_format" not in json.loads(seen[0].content)

    def test_repr_hides_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        llm = _llm(httpx.MockTransport(lambda _r: httpx.Response(200)), monkeypatch)
        assert "sk-test" not in repr(llm)
        assert repr(llm) == "OpenAICompatibleLLM(model='test-model')"
