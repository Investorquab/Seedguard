import json
import os

import pytest

from seedguard import detectors as d
from seedguard.detectors import REDACT, WARN, detect_all

from .vectors import EVM_KEY, SEED_12, SEED_12_BAD, SEED_24, TX_HASH, WIF, XPRV


def kinds(text, **kw):
    return [(f.kind, f.action) for f in detect_all(text, **kw)]


# -- BIP39 -------------------------------------------------------------------

def test_wordlist_is_canonical():
    words = d.bip39_words()
    assert len(words) == 2048
    assert words["abandon"] == 0 and words["zoo"] == 2047


def test_checksum_vectors():
    assert d.bip39_checksum_ok(SEED_12.split())
    assert d.bip39_checksum_ok(SEED_24.split())
    assert not d.bip39_checksum_ok(SEED_12_BAD.split())


def test_seed_in_sentence():
    text = f"hey my wallet words are {SEED_12} pls check balance"
    fs = detect_all(text)
    assert [(f.kind, f.confidence) for f in fs] == [("SEED", "high")]
    assert fs[0].value == SEED_12


def test_seed_numbered_multiline():
    numbered = "\n".join(f"{i + 1}. {w}" for i, w in enumerate(SEED_24.split()))
    fs = detect_all(numbered)
    assert [f.kind for f in fs] == ["SEED"]
    assert fs[0].value.startswith("abandon") and fs[0].value.endswith("art")


def test_seed_comma_separated_uppercase():
    fs = detect_all(SEED_12.upper().replace(" ", ", "))
    assert [f.kind for f in fs] == ["SEED"]


def test_seed_bad_checksum_exact_length_still_redacted():
    fs = detect_all(SEED_12_BAD)
    assert [(f.kind, f.confidence, f.action) for f in fs] == [("SEED", "medium", REDACT)]


def test_normal_prose_not_seed():
    prose = ("Can you help me write a short story about a brave knight who must cross a dark forest "
             "to find a lost child before winter arrives in the old village by the river")
    assert [f for f in detect_all(prose) if f.kind == "SEED"] == []


# -- hex keys ----------------------------------------------------------------

def test_evm_key_with_context():
    assert kinds(f"PRIVATE_KEY={EVM_KEY}")[0] == ("ENV_SECRET", REDACT) or \
        kinds(f"PRIVATE_KEY={EVM_KEY}")[0] == ("EVM_KEY", REDACT)
    assert kinds(f"here is my private key {EVM_KEY}") == [("EVM_KEY", REDACT)]


def test_tx_hash_untouched():
    assert kinds(f"tx hash {TX_HASH} confirmed") == []
    assert kinds(f"see {TX_HASH}") == []  # 0x + no context = probably a hash


def test_bare_hex_no_context_warns():
    bare = EVM_KEY[2:]
    assert kinds(f"value: {bare}") == [("HEX_KEY", WARN)]
    assert kinds(f"sha256 {bare}") == []


# -- bitcoin / solana --------------------------------------------------------

def test_wif_and_xprv():
    assert kinds(f"import {WIF} into electrum") == [("WIF", REDACT)]
    assert kinds(XPRV) == [("XPRV", REDACT)]
    broken = WIF[:-1] + ("j" if WIF[-1] != "j" else "k")
    assert kinds(broken) == []


def test_solana_base58_secret():
    raw = os.urandom(64)
    key = d.b58encode(raw)
    assert kinds(f"solana key {key}") == [("SOL_KEY", REDACT)]
    assert kinds(f"my phantom private key is {key}") == [("SOL_KEY", REDACT)]


def test_solana_signature_not_redacted():
    sig = d.b58encode(os.urandom(64))  # tx signatures are 64-byte base58 too
    assert kinds(f"tx signature {sig} confirmed") == []
    assert kinds(f"https://solscan.io/tx/{sig}") == []
    assert kinds(f"result: {sig}") == [("SOL_KEY", WARN)]  # no context -> warn only


def test_near_secret_key():
    sk = "ed25519:" + d.b58encode(os.urandom(64))
    pk = "ed25519:" + d.b58encode(os.urandom(32))
    fs = detect_all(f"near credentials {sk}")
    assert [(f.kind, f.value) for f in fs] == [("NEAR_KEY", sk)]
    assert kinds(f"public key {pk}") == []


def test_solana_address_not_flagged():
    addr = d.b58encode(os.urandom(32))
    assert kinds(f"send to {addr}") == []


def test_solana_keypair_json():
    arr = json.dumps(list(os.urandom(64)))
    assert kinds(f"id.json: {arr}") == [("SOL_KEYPAIR", REDACT)]


# -- PEM / API keys / env ----------------------------------------------------

def test_pem():
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
    assert kinds(pem) == [("PEM_KEY", REDACT)]
    escaped = pem.replace("\n", "\\n")  # as it appears inside JSON strings
    assert kinds(escaped) == [("PEM_KEY", REDACT)]


@pytest.mark.parametrize("key,detail", [
    ("sk-ant-api03-" + "a" * 40, "anthropic"),
    ("sk-or-v1-" + "ab" * 32, "openrouter"),
    ("sk-proj-" + "Z" * 40, "openai"),
    ("ghp_" + "x" * 36, "github"),
    ("AKIA" + "ABCDEFGHIJKLMNOP", "aws"),
    ("123456789:AA" + "b" * 33, "telegram-bot"),
    ("AIza" + "c" * 35, "google"),
])
def test_api_keys(key, detail):
    fs = detect_all(f"use {key} please")
    assert [(f.kind, f.detail) for f in fs] == [("API_KEY", detail)]


def test_env_file():
    env = 'OPENAI_MODEL=gpt-4\nDB_PASSWORD="hunter2hunter2"\nexport STRIPE_SECRET=abcdefgh12345\nKEY_PATH=/home/me/key.pem\nMAX_TOKENS=4096\n'
    fs = detect_all(env)
    assert [(f.kind, f.detail, f.value) for f in fs] == [
        ("ENV_SECRET", "DB_PASSWORD", "hunter2hunter2"),
        ("ENV_SECRET", "STRIPE_SECRET", "abcdefgh12345"),
    ]


def test_json_config():
    fs = detect_all('{"private_key": "super-secret-value-123", "public_key": "abcdefghijk"}')
    assert [(f.detail, f.value) for f in fs] == [("private_key", "super-secret-value-123")]


# -- OTP ---------------------------------------------------------------------

def test_otp():
    assert kinds("Your verification code is 482913. It expires in 10 minutes.") == [("OTP", REDACT)]
    assert kinds("Use 2FA code: 7712") == [("OTP", REDACT)]
    assert kinds("HTTP status code 404 on port 8080") == []
    assert kinds("I was born in 1994 and have 3 cats") == []


def test_otp_can_be_disabled():
    assert kinds("Your verification code is 482913.", enabled=["seed"]) == []


# -- idempotency -------------------------------------------------------------

def test_placeholders_never_rematched():
    text = "PRIVATE_KEY=[[sg:EVM_KEY_abc123]] and [[sg:SEED_00ff00]]"
    assert detect_all(text) == []
