"""Per-session isolation (review blocker #2).

The vault is keyed by conversation id. On a multi-user gateway one chat must
never see, arm, or rehydrate another chat's secrets; a placeholder that leaks
from chat A into chat B must stay locked in B.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from seedguard.commands import make_handler
from seedguard.hooks import NO_SESSION, build_callbacks, session_of
from seedguard.redact import placeholders_in
from seedguard.vault import DEFAULT_SESSION, Vault

from .vectors import EVM_KEY, SEED_12


# -- real gateway shapes ------------------------------------------------------
# These mirror the real ``gateway.session.Platform`` / ``SessionSource`` and
# ``gateway.platforms.event.MessageEvent`` attributes: the chat identity lives on
# ``event.source`` (platform.value, chat_id, thread_id, user_id), NOT on the event
# itself. Hermes core isn't importable in CI, so we reproduce the shape faithfully.

class _Platform(Enum):
    TELEGRAM = "telegram"
    DISCORD = "discord"
    LOCAL = "local"


@dataclass
class _SessionSource:
    platform: _Platform
    chat_id: str
    thread_id: Optional[str] = None
    user_id: Optional[str] = None
    chat_type: str = "dm"
    shared_session: bool = False


@dataclass
class _MessageEvent:
    text: str
    source: Optional[_SessionSource] = None


def _event(text, **src):
    return _MessageEvent(text=text, source=_SessionSource(**src))


# -- session_of ---------------------------------------------------------------

def test_session_of_offgateway_prefers_session_id():
    # CLI / programmatic callers: an explicit id, else the single local session.
    assert session_of({"session_id": "chatA"}) == "chatA"
    assert session_of({"session": 42}) == "42"
    assert session_of({}) == DEFAULT_SESSION


def test_session_of_reads_gateway_event_source():
    # Inbound: the key comes from event.source, not a (nonexistent) event.session_id.
    key = session_of({}, event=_event("hi", platform=_Platform.TELEGRAM,
                                       chat_id="999", user_id="u1"))
    assert key not in (DEFAULT_SESSION, NO_SESSION)
    assert "telegram" in key and "999" in key


def test_gateway_inbound_command_and_turn_paths_agree(monkeypatch):
    # The headline flow: a secret pasted in Telegram, armed from that chat, used by a
    # tool. All three paths must compute the SAME key for the same chat.
    src = dict(platform=_Platform.TELEGRAM, chat_id="555", thread_id="7", user_id="u9")

    inbound = session_of({}, event=_event("hi", **src))
    command = session_of({"source": _SessionSource(**src)}, command=True)

    # Turn/tool path reads the identity the gateway bound into HERMES_SESSION_* vars
    # (gateway/run.py binds them from this same SessionSource as ``str(x) if x else ""``).
    bound = {
        "HERMES_SESSION_PLATFORM": "telegram",
        "HERMES_SESSION_CHAT_ID": "555",
        "HERMES_SESSION_THREAD_ID": "7",
        "HERMES_SESSION_USER_ID": "u9",
    }
    monkeypatch.setattr("seedguard.hooks._session_env",
                        lambda: (lambda name, default="": bound.get(name, default)))
    turn = session_of({"session_id": "ignored-when-bound", "platform": "telegram"})

    assert inbound == command == turn
    assert turn not in (DEFAULT_SESSION, NO_SESSION)


def test_shared_group_chat_key_parity(monkeypatch):
    # In a shared (non-DM) chat, Hermes' session_env_source strips the user from the
    # turn-path route (HERMES_SESSION_USER_ID=""), while the inbound event and the
    # slash command still carry the sender. The vault key must match anyway, or a
    # secret armed in a group could never be released to a tool there.
    src = _SessionSource(_Platform.TELEGRAM, chat_id="group1", user_id="sender42",
                         chat_type="group", shared_session=True)
    inbound = session_of({}, event=_MessageEvent(text="hi", source=src))
    command = session_of({"source": src}, command=True)

    bound = {  # what the gateway binds for a shared chat: user id dropped
        "HERMES_SESSION_PLATFORM": "telegram",
        "HERMES_SESSION_CHAT_ID": "group1",
        "HERMES_SESSION_THREAD_ID": "",
        "HERMES_SESSION_USER_ID": "",
    }
    monkeypatch.setattr("seedguard.hooks._session_env",
                        lambda: (lambda name, default="": bound.get(name, default)))
    turn = session_of({})

    assert inbound == command == turn
    assert "sender42" not in turn  # the stripped user is not in the key


def test_gateway_distinct_chats_get_distinct_keys():
    a = session_of({}, event=_event("x", platform=_Platform.TELEGRAM, chat_id="1", user_id="u"))
    b = session_of({}, event=_event("x", platform=_Platform.TELEGRAM, chat_id="2", user_id="u"))
    c = session_of({}, event=_event("x", platform=_Platform.DISCORD, chat_id="1", user_id="u"))
    assert a != b != c and a != c


def test_session_of_accepts_plain_string_platform():
    # A source whose ``platform`` is already a string (no ``.value``) still keys.
    @dataclass
    class _StrSource:
        platform: str
        chat_id: str
        thread_id: Optional[str] = None
        user_id: Optional[str] = None

    key = session_of({"source": _StrSource("telegram", "42", user_id="u")}, command=True)
    assert "telegram" in key and "42" in key and key not in (DEFAULT_SESSION, NO_SESSION)


def test_cli_command_is_the_local_session():
    # cli.py dispatches /seedguard with source=None, platform="cli".
    assert session_of({"source": None, "platform": "cli", "session_id": ""}, command=True) == DEFAULT_SESSION


def test_gateway_without_chat_identity_refuses():
    # A gateway source with no chat id must never fold into the shared default.
    assert session_of({}, event=_event("x", platform=_Platform.TELEGRAM, chat_id="")) == NO_SESSION
    assert session_of({}, event=_MessageEvent(text="x", source=None)) == NO_SESSION
    assert session_of({"source": _SessionSource(_Platform.TELEGRAM, chat_id="")}, command=True) == NO_SESSION


def test_command_refuses_on_unkeyable_gateway_chat(rt):
    rt.redactor.redact_text(f"seed {SEED_12}", session="A")  # a secret exists elsewhere
    h = make_handler(rt)
    # A gateway command whose source carries no chat id: refuse, don't list A's catches.
    out = h("status", source=_SessionSource(_Platform.TELEGRAM, chat_id=""), platform="telegram")
    assert "no session" in out.lower()
    assert "SEED_" not in out


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
