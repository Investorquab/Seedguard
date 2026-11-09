"""Per-session isolation (review blocker #2).

The vault is keyed by conversation id. On a multi-user gateway one chat must
never see, arm, or rehydrate another chat's secrets; a placeholder that leaks
from chat A into chat B must stay locked in B.
"""
from seedguard.commands import make_handler
from seedguard.hooks import build_callbacks, session_of
from seedguard.redact import placeholders_in
from seedguard.vault import DEFAULT_SESSION, Vault

from .vectors import EVM_KEY, SEED_12


# -- session_of ---------------------------------------------------------------

def test_session_of_prefers_session_id():
    assert session_of({"session_id": "chatA"}) == "chatA"
    assert session_of({"session": 42}) == "42"
    assert session_of({}) == DEFAULT_SESSION


def test_session_of_reads_gateway_event():
    class Ev:
        session_id = "tg:999"
        text = "hi"

    assert session_of({}, event=Ev()) == "tg:999"


# -- vault isolation ----------------------------------------------------------

def test_secret_caught_in_one_session_is_invisible_in_another(rt):
    rt.redactor.redact_text(f"seed {SEED_12}", session="A")
    assert rt.vault.entries("A")                      # A has it
    assert rt.vault.entries("B") == []                # B does not
    assert rt.vault.entries(DEFAULT_SESSION) == []    # nor the default


def test_cross_session_placeholder_never_rehydrates(rt):
    # Chat A catches the key and arms it.
    red, _ = rt.redactor.redact_text(f"private key {EVM_KEY}", session="A")
    sid = placeholders_in(red)[0]
    ph = f"[[sg:{sid}]]"
    rt.vault.arm(sid, 5, session="A")

    # The same placeholder, pasted into chat B, must not resolve there even
    # though it is armed in A and the tool is allowed.
    new, used, locked = rt.redactor.rehydrate_obj({"command": f"use {ph}"}, "terminal", session="B")
    assert used == [] and locked == [sid]
    assert EVM_KEY not in new["command"]

    # It still works in its own session.
    new_a, used_a, _ = rt.redactor.rehydrate_obj({"command": f"use {ph}"}, "terminal", session="A")
    assert used_a == [sid] and new_a["command"].endswith(EVM_KEY)


def test_status_and_arm_scope_to_calling_session(rt):
    rt.redactor.redact_text(f"seed {SEED_12}", session="A")
    h = make_handler(rt)
    # B's status shows nothing; A's shows the secret.
    assert "No secrets caught" in h("status", session_id="B")
    assert "SEED_" in h("status", session_id="A")
    # 'arm all' from B arms nothing in A.
    h("arm all", session_id="B")
    assert not any(e.armed() for e in rt.vault.entries("A"))
    # 'forget all' from B leaves A intact.
    h("forget all", session_id="B")
    assert rt.vault.entries("A")


def test_tool_request_hook_isolates_by_session(rt):
    cb = build_callbacks(rt)
    red, _ = rt.redactor.redact_text(f"private key {EVM_KEY}", session="A")
    sid = placeholders_in(red)[0]
    rt.vault.arm(sid, 5, session="A")
    args = {"command": f"cast wallet address --private-key [[sg:{sid}]]"}
    # Same tool call arriving in chat B: locked.
    assert cb["tool_request"](tool_name="terminal", args=dict(args), session_id="B") is None
    # In chat A: released.
    out = cb["tool_request"](tool_name="terminal", args=dict(args), session_id="A")
    assert out and out["args"]["command"].endswith(EVM_KEY)


# -- entry cap (review recommendation) ---------------------------------------

def test_entry_cap_bounds_pre_auth_flood(tmp_path):
    v = Vault(state_dir=tmp_path, persist_events=False, key=b"k" * 32, max_entries_per_session=8)
    for i in range(50):
        v.register("API_KEY", f"sk-value-number-{i:04d}", session="flood")
    assert len(v.entries("flood")) == 8          # bounded
    # The most recent secret survives; the oldest was evicted.
    newest = v.secret_id("API_KEY", "sk-value-number-0049")
    assert v.get(newest, "flood") is not None
    oldest = v.secret_id("API_KEY", "sk-value-number-0000")
    assert v.get(oldest, "flood") is None
