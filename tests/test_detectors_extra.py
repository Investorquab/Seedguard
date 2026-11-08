"""Detectors added in Phase 3: Sui bech32 keys, Ethereum V3 keystore JSON,
and proof that Aptos / Tron hex keys are covered by the context hex detector.
"""
import os

from seedguard.detectors import REDACT, WARN, detect_all

from .vectors import make_keystore, make_suiprivkey


def kinds(text, **kw):
    return [(f.kind, f.action) for f in detect_all(text, **kw)]


# -- Sui (suiprivkey1..., bech32-checksummed) --------------------------------

def test_sui_privkey_detected():
    key = make_suiprivkey(os.urandom(32))
    fs = detect_all(f"import {key} into the sui wallet")
    assert [(f.kind, f.confidence, f.detail) for f in fs] == [("SUI_KEY", "high", "bech32")]
    assert fs[0].value == key


def test_sui_bad_checksum_ignored():
    key = make_suiprivkey(os.urandom(32))
    corrupt = key[:-1] + ("q" if key[-1] != "q" else "p")
    assert [f for f in detect_all(corrupt) if f.kind == "SUI_KEY"] == []


def test_sui_truncated_ignored():
    key = make_suiprivkey(os.urandom(32))
    assert [f for f in detect_all(key[:40]) if f.kind == "SUI_KEY"] == []


def test_sui_can_be_disabled():
    key = make_suiprivkey(os.urandom(32))
    assert [f for f in detect_all(f"key {key}", enabled=["seed"]) if f.kind == "SUI_KEY"] == []


def test_sui_redacts_to_placeholder(rt):
    key = make_suiprivkey(os.urandom(32))
    red, fs = rt.redactor.redact_text(f"my sui key {key}")
    assert key not in red and "[[sg:SUI_KEY_" in red


# -- Ethereum V3 keystore JSON -----------------------------------------------

def test_keystore_ciphertext_redacted():
    cipher = "a1b2c3d4" * 8  # 64 hex = 32 bytes
    ks = make_keystore(cipher)
    fs = [f for f in detect_all(ks) if f.kind == "KEYSTORE"]
    assert [(f.detail, f.value) for f in fs] == [("eth-keystore-v3", cipher)]


def test_keystore_redaction_hides_ciphertext(rt):
    cipher = "deadbeef" * 8
    ks = make_keystore(cipher)
    red, _ = rt.redactor.redact_text(ks)
    assert cipher not in red and '"kdf":"scrypt"' in red  # structure survives, secret gone


def test_lone_ciphertext_without_kdf_not_flagged():
    # A "ciphertext" field with no keystore markers is not treated as sensitive.
    assert [f for f in detect_all('{"ciphertext": "%s"}' % ("a" * 64)) if f.kind == "KEYSTORE"] == []


# -- Aptos / Tron: covered by the context-hex detector -----------------------

def test_aptos_hex_key_with_context():
    # Aptos ed25519 keys are shown as 0x + 64 hex, usually labelled.
    key = "0x" + "9" * 64
    assert kinds(f"aptos private key: {key}") == [("EVM_KEY", REDACT)]


def test_tron_hex_key_with_context():
    # Tron private keys are 64 hex (no 0x prefix).
    key = "b" * 64
    assert kinds(f"tron wallet private key {key}") == [("HEX_KEY", REDACT)]


def test_bare_keystore_hex_still_safe_without_context():
    # 64-hex with no key context and no keystore JSON -> warn only, never silent redact.
    assert kinds("value " + "c" * 64) == [("HEX_KEY", WARN)]
