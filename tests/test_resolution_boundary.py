"""Where placeholders can and cannot resolve, and the honest detection limits.

Answers the common review question "can a placeholder be resolved somewhere
unexpected later?" — no: only `tool_request` ever rehydrates, and only for an
allowlisted tool, an armed secret, in the catching session. Also pins the
known detection gaps (encoded / split secrets) so a future change is noticed.
"""
import base64

from seedguard.hooks import build_callbacks
from seedguard.redact import placeholders_in

from .vectors import EVM_KEY


def _armed_placeholder(rt):
    red, _ = rt.redactor.redact_text(f"private key {EVM_KEY}")
    sid = placeholders_in(red)[0]
    rt.vault.arm(sid, 5)
    return f"[[sg:{sid}]]", sid


# -- only tool_request resolves ----------------------------------------------

def test_no_hook_but_tool_request_turns_a_placeholder_back(rt):
    cb = build_callbacks(rt)
    ph, sid = _armed_placeholder(rt)

    # None of the output/request hooks may ever reveal the real value, even
    # though the secret is armed. They only redact; they never rehydrate.
    assert cb["transform_tool_result"](result=f"see {ph}", tool_name="terminal") is None
    assert cb["transform_terminal_output"](output=f"see {ph}") is None
    assert cb["transform_llm_output"](response_text=f"see {ph}") is None
    assert cb["llm_request"](request={"messages": [{"role": "user", "content": ph}]}) is None

    # Only the allowlisted tool call resolves it.
    out = cb["tool_request"](tool_name="terminal", args={"command": f"use {ph}"})
    assert out and out["args"]["command"].endswith(EVM_KEY)


def test_placeholder_in_a_later_message_is_not_a_leak(rt):
    # A placeholder echoed back into a provider request stays a placeholder: the
    # provider (and model) never see the value again.
    cb = build_callbacks(rt)
    ph, _ = _armed_placeholder(rt)
    res = cb["llm_request"](request={"messages": [{"role": "assistant", "content": f"earlier you gave {ph}"}]})
    assert res is None  # nothing to redact, nothing rehydrated


# -- honest detection gaps (characterization) --------------------------------

def test_base64_encoded_secret_is_not_detected(rt):
    # Known limitation #6: an encoded secret slips pattern detection.
    enc = base64.b64encode(EVM_KEY.encode()).decode()
    red, findings = rt.redactor.redact_text(f"payload {enc}")
    assert enc in red                                   # passed through unchanged
    assert not any(f.action == "redact" for f in findings)


def test_secret_split_across_outputs_is_not_reassembled(rt):
    # Known limitation #6: a key split across two separate outputs — each half
    # alone doesn't look like a key — is not caught, while the whole key is.
    cb = build_callbacks(rt)
    half1, half2 = EVM_KEY[:34], EVM_KEY[34:]
    # Same key-context on all three, so the only difference is wholeness.
    assert cb["transform_terminal_output"](output=f"private key {half1}") is None
    assert cb["transform_terminal_output"](output=f"private key {half2}") is None
    whole = cb["transform_terminal_output"](output=f"private key {EVM_KEY}")
    assert whole is not None and EVM_KEY not in whole   # the full key IS caught
