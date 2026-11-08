from seedguard.commands import make_handler
from seedguard.redact import placeholders_in

from .vectors import EVM_KEY, SEED_12


def test_status_empty(rt):
    out = make_handler(rt)("")
    assert "Seedguard is on" in out and "No secrets caught" in out


def test_status_never_shows_values(rt):
    rt.redactor.redact_text(f"seed {SEED_12} and private key {EVM_KEY}")
    out = make_handler(rt)("status")
    assert "SEED_" in out and "EVM_KEY_" in out
    assert SEED_12 not in out and EVM_KEY not in out


def test_arm_disarm(rt):
    red, _ = rt.redactor.redact_text(f"private key {EVM_KEY}")
    sid = placeholders_in(red)[0]
    h = make_handler(rt)
    assert "Armed" in h(f"arm {sid} 3")
    assert rt.vault.get(sid).armed()
    assert "Locked" in h("disarm")
    assert not rt.vault.get(sid).armed()
    assert "No protected secret" in h("arm nope")


def test_arm_accepts_placeholder_form(rt):
    red, _ = rt.redactor.redact_text(f"private key {EVM_KEY}")
    sid = placeholders_in(red)[0]
    assert "Armed" in make_handler(rt)(f"arm [[sg:{sid}]]")


def test_test_subcommand(rt):
    out = make_handler(rt)(f"test my seed is {SEED_12}")
    assert "SEED" in out and SEED_12 not in out
    assert rt.vault.recent_events() == []  # test mode doesn't log


def test_log_and_forget(rt):
    rt.redactor.redact_text(f"seed {SEED_12}", where="unit")
    h = make_handler(rt)
    assert "unit" in h("log 5")
    assert "Forgot 1" in h("forget all")
    assert rt.vault.entries() == []
