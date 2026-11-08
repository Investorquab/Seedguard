"""Every hook swallows its own internal errors (returns None, never raises),
so a Seedguard bug can never crash the agent loop. Layer 3 (llm_execution)
is the one exception -- it fails *closed* and is covered in test_hardening.
"""
import pytest

from seedguard.hooks import build_callbacks

from .vectors import EVM_KEY


def _boom(*a, **k):
    raise RuntimeError("seedguard internal error")


def test_llm_request_swallows_errors(rt, monkeypatch):
    cb = build_callbacks(rt)
    monkeypatch.setattr(rt.redactor, "redact_obj", _boom)
    assert cb["llm_request"](request={"messages": [{"content": f"seed {EVM_KEY}"}]}) is None


def test_tool_request_swallows_errors(rt, monkeypatch):
    cb = build_callbacks(rt)
    monkeypatch.setattr(rt.redactor, "rehydrate_obj", _boom)
    args = {"command": "use [[sg:EVM_KEY_aabbcc]]"}
    assert cb["tool_request"](tool_name="terminal", args=args) is None


def test_pre_tool_call_swallows_errors(rt, monkeypatch):
    cb = build_callbacks(rt)
    monkeypatch.setattr(rt.vault, "get", _boom)
    args = {"command": "use [[sg:EVM_KEY_aabbcc]]"}  # allowed tool + placeholder -> reaches vault.get
    assert cb["pre_tool_call"](tool_name="terminal", args=args) is None


def test_output_hooks_swallow_errors(rt, monkeypatch):
    cb = build_callbacks(rt)
    monkeypatch.setattr(rt.redactor, "redact_text", _boom)
    assert cb["transform_terminal_output"](output="cat .env output") is None
    assert cb["transform_tool_result"](result="some result", tool_name="x") is None
    assert cb["transform_llm_output"](response_text="a reply") is None


def test_gateway_swallows_errors(rt, monkeypatch):
    from types import SimpleNamespace
    cb = build_callbacks(rt)
    monkeypatch.setattr(rt.redactor, "redact_text", _boom)
    assert cb["pre_gateway_dispatch"](event=SimpleNamespace(text="some message")) is None
