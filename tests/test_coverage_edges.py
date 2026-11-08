"""Edge-case and branch tests: error swallowing, alternate request shapes,
vault persistence, and the small helpers. These close the fail-safe paths.
"""
import json
from types import SimpleNamespace

import pytest

from seedguard.hooks import build_callbacks
from seedguard.redact import MAX_SCAN_CHARS, stub_request
from seedguard.vault import Vault, placeholder

from .vectors import EVM_KEY, SEED_12


# -- Redactor helpers --------------------------------------------------------

def test_contains_secret_true_false_and_skips(rt):
    assert rt.redactor.contains_secret({"messages": [{"content": f"seed {SEED_12}"}]})
    assert not rt.redactor.contains_secret({"messages": [{"content": "hello world"}]})
    # auth-bearing keys are skipped, so a key under api_key is not "contained"
    assert not rt.redactor.contains_secret({"api_key": "sk-ant-" + "a" * 40})
    # big inline data: payloads are ignored
    assert not rt.redactor.contains_secret({"content": "data:image/png;base64," + "A" * 400})


def test_redact_text_over_limit_is_passthrough(rt):
    big = "x" * (MAX_SCAN_CHARS + 1)
    out, findings = rt.redactor.redact_text(big)
    assert out == big and findings == []


def test_redact_obj_skips_data_urls(rt):
    obj = {"content": "data:image/png;base64," + "Q" * 500}
    new, findings = rt.redactor.redact_obj(obj)
    assert new == obj and findings == []


def test_stub_request_anthropic_shape():
    req = {"model": "claude", "system": f"secret {EVM_KEY}",
           "messages": [{"role": "user", "content": "hi"}]}
    stub = stub_request(req)
    assert stub["system"] == "You are a safety stub."
    assert EVM_KEY not in str(stub) and stub["model"] == "claude"


# -- Hook error-swallowing (return None, never raise) ------------------------

def test_llm_request_ignores_non_dict(rt):
    cb = build_callbacks(rt)
    assert cb["llm_request"](request="not a dict") is None
    assert cb["llm_request"](request=None) is None


def test_tool_request_ignores_non_dict_args(rt):
    cb = build_callbacks(rt)
    assert cb["tool_request"](tool_name="terminal", args="nope") is None
    assert cb["tool_request"](tool_name="terminal", args={"command": "ls"}) is None


def test_transform_hooks_ignore_non_str_and_noop(rt):
    cb = build_callbacks(rt)
    assert cb["transform_terminal_output"](output=None) is None
    assert cb["transform_tool_result"](result=123, tool_name="x") is None
    assert cb["transform_llm_output"](response_text=None) is None
    assert cb["transform_llm_output"](response_text="nothing secret here") is None


def test_gateway_disabled_returns_none(rt):
    rt.cfg["gateway_inbound"] = False
    cb = build_callbacks(rt)
    assert cb["pre_gateway_dispatch"](event=SimpleNamespace(text=f"seed {SEED_12}")) is None


def test_gateway_ignores_eventless(rt):
    cb = build_callbacks(rt)
    assert cb["pre_gateway_dispatch"](event=SimpleNamespace(text=None)) is None
    assert cb["pre_gateway_dispatch"](event=object()) is None


# -- pre_tool_call explanation branches --------------------------------------

def test_pre_tool_call_unknown_id_message(rt):
    cb = build_callbacks(rt)
    block = cb["pre_tool_call"](tool_name="terminal", args={"c": "[[sg:EVM_KEY_aabbcc]]"})
    assert block["action"] == "block" and "unknown in this session" in block["message"]


def test_pre_tool_call_never_mode_message(rt):
    rt.cfg["rehydrate"] = "never"
    cb = build_callbacks(rt)
    red, _ = rt.redactor.redact_text(f"private key {EVM_KEY}")
    sid = red.split("[[sg:")[1].split("]]")[0]
    block = cb["pre_tool_call"](tool_name="terminal", args={"c": placeholder(sid)})
    assert "rehydration is disabled" in block["message"]


# -- Vault persistence -------------------------------------------------------

def test_events_persisted_to_disk(tmp_path):
    v = Vault(state_dir=tmp_path, persist_events=True)
    sid = v.register("EVM_KEY", EVM_KEY)
    v.log("test", "EVM_KEY", sid, "redact")
    log = (tmp_path / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert log and json.loads(log[-1])["id"] == sid
    # the real secret value is never written
    assert EVM_KEY not in (tmp_path / "events.jsonl").read_text(encoding="utf-8")


def test_key_file_persists_stable_ids(tmp_path):
    v1 = Vault(state_dir=tmp_path, persist_events=False)
    sid1 = v1.secret_id("EVM_KEY", EVM_KEY)
    assert (tmp_path / "hmac.key").exists()
    v2 = Vault(state_dir=tmp_path, persist_events=False)   # reloads the same key
    assert v2.secret_id("EVM_KEY", EVM_KEY) == sid1


def test_explicit_key_is_used(tmp_path):
    v = Vault(state_dir=tmp_path, persist_events=False, key=b"k" * 32)
    assert not (tmp_path / "hmac.key").exists()  # no file written when key given
    assert v.secret_id("EVM_KEY", EVM_KEY).startswith("EVM_KEY_")
