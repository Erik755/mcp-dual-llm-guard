"""Keep the README honest: run the shipped demos and check their key claims."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


async def test_email_injection_demo(capsys: pytest.CaptureFixture[str]) -> None:
    demo = _load("email_injection_demo")
    await demo.main()
    out = capsys.readouterr().out
    naive, guarded = out.split("[2] Dual LLM guard")
    assert "to='attacker@evil.com'" in naive
    guarded_section = guarded.split("[3]")[0]
    assert "to='boss@acme.example'" in guarded_section
    assert "to='attacker@evil.com'" not in guarded_section
    assert "privileged LLM ever saw the attacker address? False" in out
    assert "BLOCKED  TaintFlowViolation" in out
    assert "BLOCKED  UntrustedContentInPrivilegedContext" in out


async def test_mcp_tool_poisoning_demo(capsys: pytest.CaptureFixture[str]) -> None:
    pytest.importorskip("mcp")
    demo = _load("mcp_tool_poisoning_demo")
    await demo.main()
    out = capsys.readouterr().out
    assert "registered: ['read_email']" in out
    assert "REJECTED fetch_url: ToolPoisoningDetected" in out
    assert "REJECTED read_email: ToolManifestChanged" in out
    assert "planner saw 'evil.example'? False" in out


async def test_live_llm_demo_exits_cleanly_without_api_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("httpx")
    demo = _load("live_llm_demo")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["live_llm_demo.py"])
    with pytest.raises(SystemExit) as excinfo:
        await demo.main()
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "OPENAI_API_KEY is not set" in captured.err
    assert "export OPENAI_API_KEY=" in captured.err
    assert "--no-key" in captured.err
    assert "examples/email_injection_demo.py" in captured.err
