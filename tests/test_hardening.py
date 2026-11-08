"""Phase 3 hardening: fail-closed enforcement, rehydration security,
concurrency and performance. These exercise the paths that keep secrets in
even when something goes wrong.
"""
import threading
import time

import pytest

from seedguard.hooks import build_callbacks
from seedguard.redact import STUB_TEXT, placeholders_in, stub_request

from .vectors import EVM_KEY, SEED_12, make_suiprivkey


# ---------------------------------------------------------------------------
# Fail-closed: next_call runs exactly once, never carrying a secret
# ---------------------------------------------------------------------------

def _count_calls(rt, request, break_redactor=False, break_stub=False, monkeypatch=None):
    cb = build_callbacks(rt)
    calls = []
    if break_redactor:
        monkeypatch.setattr(rt.redactor, "redact_obj",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    if break_stub:
        monkeypatch.setattr("seedguard.hooks.stub_request",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stub boom")))
    cb["llm_execution"](request=request, next_call=lambda r: calls.append(r))
    return calls


def test_execution_calls_next_exactly_once_on_clean(rt):
    calls = _count_calls(rt, {"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert len(calls) == 1


def test_execution_calls_next_exactly_once_on_secret(rt):
    req = {"model": "m", "messages": [{"role": "user", "content": f"seed {SEED_12}"}]}
    calls = _count_calls(rt, req)
    assert len(calls) == 1 and SEED_12 not in str(calls[0])


def test_execution_fails_closed_responses_api_shape(rt, monkeypatch):
    # OpenAI Responses API uses input/instructions, not messages.
    req = {"model": "m", "input": [{"role": "user", "content": f"key {EVM_KEY}"}],
           "instructions": "be helpful"}
    calls = _count_calls(rt, req, break_redactor=True, monkeypatch=monkeypatch)
    assert len(calls) == 1
    sent = calls[0]
    assert EVM_KEY not in str(sent)
    assert sent["input"] == [{"role": "user", "content": STUB_TEXT}]
    assert sent["instructions"] == "You are a safety stub."
    assert "messages" not in sent


def test_execution_fails_closed_even_if_stub_fails(rt, monkeypatch):
    req = {"model": "m", "messages": [{"role": "user", "content": f"seed {SEED_12}"}]}
    calls = _count_calls(rt, req, break_redactor=True, break_stub=True, monkeypatch=monkeypatch)
    assert len(calls) == 1
    sent = calls[0]
    assert SEED_12 not in str(sent)
    assert sent == {"messages": [{"role": "user", "content": "[Seedguard blocked this request.]"}]}


def test_stub_request_strips_tools_but_keeps_transport():
    req = {"model": "m", "messages": [{"role": "user", "content": "x"}],
           "tools": [{"type": "function"}], "temperature": 0.7, "stream": True}
    stub = stub_request(req)
    assert "tools" not in stub and stub["model"] == "m"
    assert stub["temperature"] == 0.7 and stub["stream"] is True


def test_execution_handles_streaming_kwargs(rt):
    req = {"model": "m", "stream": True, "stream_options": {"include_usage": True},
           "messages": [{"role": "user", "content": f"seed {SEED_12}"}]}
    calls = _count_calls(rt, req)
    assert len(calls) == 1 and calls[0]["stream"] is True and SEED_12 not in str(calls[0])


# ---------------------------------------------------------------------------
# Rehydration security
# ---------------------------------------------------------------------------

def _ph(rt, text):
    red, _ = rt.redactor.redact_text(text)
    sid = placeholders_in(red)[0]
    return f"[[sg:{sid}]]", sid


def test_unknown_placeholder_never_resolves(rt):
    new, used, locked = rt.redactor.rehydrate_obj({"c": "[[sg:EVM_KEY_abcdef]]"}, "terminal")
    assert used == [] and locked == ["EVM_KEY_abcdef"]
    assert new["c"] == "[[sg:EVM_KEY_abcdef]]"


def test_non_allowlisted_tool_never_resolves_even_when_armed(rt):
    ph, sid = _ph(rt, f"private key {EVM_KEY}")
    rt.vault.arm(sid, 5)
    new, used, locked = rt.redactor.rehydrate_obj({"url": ph}, "web_fetch")
    assert used == [] and locked == [sid] and EVM_KEY not in str(new)


def test_mixed_armed_and_locked_only_releases_armed(rt):
    ph1, sid1 = _ph(rt, f"private key {EVM_KEY}")
    sui = make_suiprivkey(b"\x11" * 32)
    ph2, sid2 = _ph(rt, f"sui key {sui}")
    rt.vault.arm(sid1, 5)  # arm only the first
    args = {"cmd": f"a {ph1} b {ph2}"}
    new, used, locked = rt.redactor.rehydrate_obj(args, "terminal")
    assert used == [sid1] and locked == [sid2]
    assert EVM_KEY in new["cmd"] and sui not in new["cmd"] and ph2 in new["cmd"]


def test_pre_tool_call_blocks_locked_on_allowed_tool(rt):
    cb = build_callbacks(rt)
    ph, sid = _ph(rt, f"private key {EVM_KEY}")
    block = cb["pre_tool_call"](tool_name="terminal", args={"command": f"use {ph}"})
    assert block["action"] == "block" and sid in block["message"]
    assert rt.stats["tool_blocks"] == 1


def test_always_mode_releases_without_arming(rt):
    rt.cfg["rehydrate"] = "always"
    ph, sid = _ph(rt, f"private key {EVM_KEY}")
    new, used, _ = rt.redactor.rehydrate_obj({"c": ph}, "terminal")
    assert used == [sid] and new["c"].endswith(EVM_KEY)


def test_forget_stops_resolution(rt):
    ph, sid = _ph(rt, f"private key {EVM_KEY}")
    rt.vault.arm(sid, 5)
    rt.vault.forget(sid)
    new, used, locked = rt.redactor.rehydrate_obj({"c": ph}, "terminal")
    assert used == [] and locked == [sid]


# ---------------------------------------------------------------------------
# Concurrency: the vault/redactor serve many sessions at once
# ---------------------------------------------------------------------------

def test_vault_stable_ids_under_threads(rt):
    results = []

    def worker():
        sid = rt.vault.register("EVM_KEY", EVM_KEY, "x")
        results.append(sid)

    threads = [threading.Thread(target=worker) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(results)) == 1              # one id for one secret
    assert rt.vault.get(results[0]).hits == 40  # every hit counted


def test_concurrent_redaction_never_leaks(rt):
    errors = []

    def worker(i):
        try:
            red, _ = rt.redactor.redact_text(f"session {i} seed {SEED_12} key {EVM_KEY}")
            assert SEED_12 not in red and EVM_KEY not in red
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


# ---------------------------------------------------------------------------
# Performance: a big request is cleaned fast, and repeats hit the cache
# ---------------------------------------------------------------------------

def test_one_megabyte_redacted_and_cached(rt):
    blob = ("The quiet river carried the small boat past the old stone bridge. " * 20
            + f"\nPRIVATE_KEY={EVM_KEY}\n") * 800
    assert len(blob) > 1_000_000

    t0 = time.perf_counter()
    red, _ = rt.redactor.redact_text(blob)
    cold = time.perf_counter() - t0
    assert EVM_KEY not in red
    # A full 1 MB scan stays well under the interactive budget even on a slow
    # laptop / CI runner. (It is ~1.3 s here; real provider requests are far
    # smaller, and repeats hit the cache below.)
    assert cold < 4.0, f"cold scan took {cold:.3f}s"

    t1 = time.perf_counter()
    red2, _ = rt.redactor.redact_text(blob)
    warm = time.perf_counter() - t1
    assert red2 == red
    assert warm < 0.05, f"cache hit took {warm:.4f}s"   # near-instant on repeat
    assert warm < cold / 5                               # and dramatically faster
