"""Secret detectors for Seedguard.

Every detector returns ``Finding`` objects that point at the exact span to
replace. Detectors are pure functions of the input text: no I/O, no globals
that change at runtime. That keeps them easy to unit-test and safe to cache.

Design rules
------------
* Prefer *verifiable* formats. BIP39 phrases are checked against the
  checksum, WIF / xprv keys against base58check, Solana secrets by decoded
  length. Verified hits are ``high`` confidence and always redacted.
* Ambiguous formats (a bare 64-hex string could be a private key *or* a
  sha256 digest / tx hash) need surrounding context before we redact. With no
  context they are reported as ``warn`` so we never break crypto workflows by
  hiding every transaction hash.
* Never match our own placeholders, so redaction is idempotent.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

PLACEHOLDER_RE = re.compile(r"\[\[sg:([A-Z0-9_]+)_([0-9a-f]{6})\]\]")

REDACT = "redact"
WARN = "warn"


@dataclass(frozen=True)
class Finding:
    kind: str           # SEED, EVM_KEY, HEX_KEY, WIF, XPRV, SOL_KEY, SOL_KEYPAIR, PEM_KEY, API_KEY, ENV_SECRET, OTP
    start: int
    end: int
    value: str          # exact text in [start, end) that would be replaced
    confidence: str     # "high" | "medium" | "low"
    action: str         # REDACT | WARN
    detail: str = ""    # e.g. "bip39-checksum", "openai", "PRIVATE_KEY"

    @property
    def length(self) -> int:
        return self.end - self.start


# ---------------------------------------------------------------------------
# base58 helpers (bitcoin alphabet)
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
_B58 = "[1-9A-HJ-NP-Za-km-z]"


def b58decode(s: str) -> Optional[bytes]:
    num = 0
    for ch in s:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            return None
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def b58check_payload(s: str) -> Optional[bytes]:
    raw = b58decode(s)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


# ---------------------------------------------------------------------------
# bech32 helpers (BIP173) -- used by Sui private keys (suiprivkey1...)
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: Sequence[int]) -> int:
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_verify(hrp: str, data: Sequence[int]) -> bool:
    # Sui private keys use standard bech32 (checksum constant 1), not bech32m.
    return _bech32_polymod(_bech32_hrp_expand(hrp) + list(data)) == 1


# ---------------------------------------------------------------------------
# BIP39
# ---------------------------------------------------------------------------

_WORDLIST_PATH = Path(__file__).resolve().parent / "data" / "bip39_english.txt"
_VALID_SEED_LENGTHS = (24, 21, 18, 15, 12)


@lru_cache(maxsize=1)
def bip39_words() -> Dict[str, int]:
    words = _WORDLIST_PATH.read_text(encoding="utf-8").split()
    if len(words) != 2048:
        raise RuntimeError(f"BIP39 wordlist corrupted: {len(words)} words")
    return {w: i for i, w in enumerate(words)}


def bip39_checksum_ok(words: Sequence[str]) -> bool:
    table = bip39_words()
    if len(words) not in _VALID_SEED_LENGTHS:
        return False
    try:
        bits = "".join(format(table[w.lower()], "011b") for w in words)
    except KeyError:
        return False
    ent_len = len(bits) * 32 // 33
    entropy = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    cs = bits[ent_len:]
    digest_bits = format(int.from_bytes(hashlib.sha256(entropy).digest(), "big"), "0256b")
    return digest_bits[: len(cs)] == cs


_WORD_RE = re.compile(r"[A-Za-z]+")
# What may sit between two words of a pasted phrase: spaces, newlines,
# commas, numbering like "1." / "2)" / "#3", quotes and dashes.
_SEED_GAP_RE = re.compile(r"^[\s,;.:\-–()\[\]#\d\"'`|]*$")


def detect_seeds(text: str) -> List[Finding]:
    table = bip39_words()
    tokens = [(m.start(), m.end(), m.group(0)) for m in _WORD_RE.finditer(text)]
    findings: List[Finding] = []

    # Build runs of consecutive BIP39 words separated only by "gap" chars.
    runs: List[List[tuple]] = []
    current: List[tuple] = []
    for tok in tokens:
        word_ok = tok[2].lower() in table
        if word_ok and current:
            gap = text[current[-1][1]: tok[0]]
            if len(gap) <= 12 and _SEED_GAP_RE.match(gap):
                current.append(tok)
                continue
        if current:
            runs.append(current)
        current = [tok] if word_ok else []
    if current:
        runs.append(current)

    for run in runs:
        if len(run) < 12:
            continue
        words = [t[2] for t in run]
        i = 0
        matched_any = False
        while i <= len(words) - 12:
            hit = None
            for length in _VALID_SEED_LENGTHS:
                if i + length <= len(words) and bip39_checksum_ok(words[i: i + length]):
                    hit = length
                    break
            if hit:
                s, e = run[i][0], run[i + hit - 1][1]
                findings.append(Finding("SEED", s, e, text[s:e], "high", REDACT, "bip39-checksum"))
                matched_any = True
                i += hit
            else:
                i += 1
        if not matched_any and len(run) in _VALID_SEED_LENGTHS:
            # Right length, wrong checksum: probably a phrase with a typo.
            # Still a secret -- redact, but mark it as unverified.
            s, e = run[0][0], run[-1][1]
            findings.append(Finding("SEED", s, e, text[s:e], "medium", REDACT, "bip39-length"))
    return findings


# ---------------------------------------------------------------------------
# Raw hex private keys (EVM / ed25519 seeds / generic 32-byte secrets)
# ---------------------------------------------------------------------------

_HEX64_RE = re.compile(r"(?<![0-9a-fA-Fx])(0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_KEY_CONTEXT = (
    "private", "priv", "secret", "signer", "mnemonic", "seed", "wallet key",
    "pk=", "pk:", "pk ", "sk=", "sk:", "key=", "key:", "key ", "_key", 'key"', "key'",
)
_NOT_KEY_CONTEXT = (
    "public", "pubkey", "pub ", "hash", "sha", "digest", "txid", "tx ", "tx:",
    "tx=", "transaction", "commit", "block", "root", "checksum", "address",
)


def _context_before(text: str, start: int, width: int = 48) -> str:
    return text[max(0, start - width): start].lower()


def detect_hex_keys(text: str) -> List[Finding]:
    out: List[Finding] = []
    for m in _HEX64_RE.finditer(text):
        ctx = _context_before(text, m.start())
        has_key = any(k in ctx for k in _KEY_CONTEXT)
        has_not = any(k in ctx for k in _NOT_KEY_CONTEXT)
        kind = "EVM_KEY" if m.group(1) else "HEX_KEY"
        if has_key and not has_not:
            out.append(Finding(kind, m.start(), m.end(), m.group(0), "high", REDACT, "hex+context"))
        elif not m.group(1) and not has_not:
            # Bare 64-hex with no context: could be a key, could be a digest.
            out.append(Finding(kind, m.start(), m.end(), m.group(0), "low", WARN, "hex-no-context"))
    return out


# ---------------------------------------------------------------------------
# Bitcoin WIF, BIP32 extended private keys
# ---------------------------------------------------------------------------

_WIF_RE = re.compile(rf"(?<!{_B58})[59cKL]{_B58}{{50,51}}(?!{_B58})")
_XPRV_RE = re.compile(rf"(?<!{_B58})[xtyzuvYZUV]prv{_B58}{{100,112}}(?!{_B58})")


def detect_wif(text: str) -> List[Finding]:
    out = []
    for m in _WIF_RE.finditer(text):
        payload = b58check_payload(m.group(0))
        if payload is None:
            continue
        if payload[0] in (0x80, 0xEF) and (
            len(payload) == 33 or (len(payload) == 34 and payload[-1] == 0x01)
        ):
            out.append(Finding("WIF", m.start(), m.end(), m.group(0), "high", REDACT, "base58check"))
    return out


def detect_xprv(text: str) -> List[Finding]:
    out = []
    for m in _XPRV_RE.finditer(text):
        payload = b58check_payload(m.group(0))
        if payload is not None and len(payload) == 78:
            out.append(Finding("XPRV", m.start(), m.end(), m.group(0), "high", REDACT, "base58check"))
    return out


# ---------------------------------------------------------------------------
# Solana secret keys
# ---------------------------------------------------------------------------

_SOL_B58_RE = re.compile(rf"(?<!{_B58}){_B58}{{85,90}}(?!{_B58})")
_SOL_ARRAY_RE = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")


_SOL_SIG_CONTEXT = ("signature", "sig ", "sig:", "sig=", "txid", "tx ", "tx:", "tx=", "/tx/",
                    "transaction", "solscan", "explorer", "solana.fm", "confirmed", "hash")


def detect_solana(text: str) -> List[Finding]:
    """Solana / NEAR ed25519 secret keys (64 bytes in base58).

    Careful: a Solana *transaction signature* is also 64 bytes in base58 and
    looks identical. Agents see signatures all the time (explorer links, tool
    output), so we only redact with key context, never with signature
    context, and merely warn when there is no context at all.
    """
    out = []
    for m in _SOL_B58_RE.finditer(text):
        raw = b58decode(m.group(0))
        if raw is None or len(raw) != 64:
            continue
        ctx = _context_before(text, m.start(), 48)
        if ctx.endswith("ed25519:"):
            # NEAR-style "ed25519:<base58>": 64 bytes = secret key (public keys are 32).
            out.append(Finding("NEAR_KEY", m.start() - 8, m.end(), text[m.start() - 8: m.end()],
                               "high", REDACT, "ed25519-64B"))
        elif any(k in ctx for k in _SOL_SIG_CONTEXT):
            continue
        elif any(k in ctx for k in _KEY_CONTEXT) or "keypair" in ctx or "phantom" in ctx:
            out.append(Finding("SOL_KEY", m.start(), m.end(), m.group(0), "high", REDACT, "base58-64B+context"))
        else:
            out.append(Finding("SOL_KEY", m.start(), m.end(), m.group(0), "low", WARN, "base58-64B-no-context"))
    for m in _SOL_ARRAY_RE.finditer(text):
        nums = [int(x) for x in re.findall(r"\d+", m.group(0))]
        if len(nums) == 64 and all(0 <= n <= 255 for n in nums):
            out.append(Finding("SOL_KEYPAIR", m.start(), m.end(), m.group(0), "high", REDACT, "json-64B"))
    return out


# ---------------------------------------------------------------------------
# PEM private keys
# ---------------------------------------------------------------------------

_PEM_RE = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----"
    r"[\s\S]+?-----END \1-----"
)


def detect_pem(text: str) -> List[Finding]:
    return [
        Finding("PEM_KEY", m.start(), m.end(), m.group(0), "high", REDACT, m.group(1).strip())
        for m in _PEM_RE.finditer(text)
    ]


# ---------------------------------------------------------------------------
# Provider / platform API keys
# ---------------------------------------------------------------------------

_API_PATTERNS = [
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openrouter", re.compile(r"sk-or-v1-[a-f0-9]{64}")),
    ("openai", re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    ("github", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}")),
    ("aws", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("slack", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("google", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("telegram-bot", re.compile(r"(?<!\d)\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])")),
    ("huggingface", re.compile(r"hf_[A-Za-z0-9]{30,}")),
]
_BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,}=*)")


def detect_api_keys(text: str) -> List[Finding]:
    out = []
    for name, rx in _API_PATTERNS:
        for m in rx.finditer(text):
            out.append(Finding("API_KEY", m.start(), m.end(), m.group(0), "high", REDACT, name))
    for m in _BEARER_RE.finditer(text):
        out.append(Finding("API_KEY", m.start(1), m.end(1), m.group(1), "high", REDACT, "bearer"))
    return out


# ---------------------------------------------------------------------------
# NAME=value assignments (.env files, shell exports, JSON configs)
# ---------------------------------------------------------------------------

# The ``{0,64}`` bounds keep this linear: two *unbounded* ``[A-Za-z0-9_]*`` runs
# around the keyword are quadratic on a long unbroken token full of keyword
# substrings, which would stall every tool-result hook on a few tens of KB.
_SECRET_NAME = r"[A-Za-z0-9_]{0,64}(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|MNEMONIC|SEED|key|secret|token|password|passwd|private|mnemonic|seed)[A-Za-z0-9_]{0,64}"
_ENV_QUOTED_RE = re.compile(rf"(?m)(?:^|(?<=\s))(?:export\s+)?({_SECRET_NAME})\s*[=:]\s*(['\"])(.{{8,}}?)\2")
_ENV_BARE_RE = re.compile(rf"(?m)(?:^|(?<=\s))(?:export\s+)?({_SECRET_NAME})\s*=\s*([^\s'\"#]{{8,}})")
_JSON_RE = re.compile(rf"([\"'])({_SECRET_NAME})\1\s*:\s*([\"'])([^\"'\n]{{8,}})\3")
_NAME_EXCLUDE = ("PATH", "FILE", "DIR", "URL", "NAME", "TYPE", "SIZE", "LENGTH", "COUNT",
                 "LIMIT", "MAX", "MIN", "USAGE", "PUBLIC", "PUBKEY", "ENABLED", "MODE")
_VALUE_EXCLUDE = re.compile(r"^(?:true|false|null|none|yes|no|\d{1,11}|\$\{?[A-Za-z_]+\}?|<[^>]*>|x+|\*+)$", re.I)


def _env_name_ok(name: str) -> bool:
    upper = name.upper()
    return not any(x in upper for x in _NAME_EXCLUDE)


def _env_value_ok(value: str) -> bool:
    if PLACEHOLDER_RE.search(value):
        return False
    if value.startswith(("/", "~", "./", "../", "http://", "https://")):
        return False
    return not _VALUE_EXCLUDE.match(value)


def detect_env(text: str) -> List[Finding]:
    out = []
    for m in _ENV_QUOTED_RE.finditer(text):
        name, value = m.group(1), m.group(3)
        if _env_name_ok(name) and _env_value_ok(value):
            out.append(Finding("ENV_SECRET", m.start(3), m.end(3), value, "high", REDACT, name))
    for m in _ENV_BARE_RE.finditer(text):
        name, value = m.group(1), m.group(2)
        if _env_name_ok(name) and _env_value_ok(value):
            out.append(Finding("ENV_SECRET", m.start(2), m.end(2), value, "high", REDACT, name))
    for m in _JSON_RE.finditer(text):
        name, value = m.group(2), m.group(4)
        if _env_name_ok(name) and _env_value_ok(value):
            out.append(Finding("ENV_SECRET", m.start(4), m.end(4), value, "high", REDACT, name))
    return out


# ---------------------------------------------------------------------------
# One-time codes (2FA / OTP / verification codes in emails and SMS)
# ---------------------------------------------------------------------------

_OTP_RE = re.compile(r"(?<![\d.:/\-])(\d{4,8})(?![\d:/\-]|\.\d|\s*(?:ms|px|kb|mb|gb|%))")
_OTP_CONTEXT = ("verification code", "verification", "code is", "code:", "your code",
                "otp", "2fa", "one-time", "one time", "passcode", "security code",
                "login code", "auth code", "confirm code", "confirmation code")
_OTP_NOT = ("error code", "status code", "exit code", "http", "port", "line ", "zip", "postal",
            "order", "invoice", "phone", "year", "version")


def detect_otp(text: str) -> List[Finding]:
    out = []
    for m in _OTP_RE.finditer(text):
        before = text[max(0, m.start() - 60): m.start()].lower()
        after = text[m.end(): m.end() + 30].lower()
        ctx = before + " " + after
        if any(k in ctx for k in _OTP_CONTEXT) and not any(k in before for k in _OTP_NOT):
            out.append(Finding("OTP", m.start(1), m.end(1), m.group(1), "medium", REDACT, "otp-context"))
    return out


# ---------------------------------------------------------------------------
# Sui private keys (Bech32 "suiprivkey1...") -- verified by checksum
# ---------------------------------------------------------------------------

# HRP "suiprivkey" has no '1' and the bech32 charset has no '1', so the single
# '1' is an unambiguous separator. 33-byte payload (flag + 32) -> 53 data chars
# + 6 checksum; we match a little loose and let the checksum decide.
_SUI_RE = re.compile(r"suiprivkey1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{50,80}")
_SUI_HRP = "suiprivkey"


def detect_sui(text: str) -> List[Finding]:
    out: List[Finding] = []
    for m in _SUI_RE.finditer(text):
        datapart = m.group(0)[len(_SUI_HRP) + 1:]
        try:
            values = [_BECH32_CHARSET.index(c) for c in datapart]
        except ValueError:
            continue
        if bech32_verify(_SUI_HRP, values):
            out.append(Finding("SUI_KEY", m.start(), m.end(), m.group(0), "high", REDACT, "bech32"))
    return out


# ---------------------------------------------------------------------------
# Ethereum V3 keystore JSON (encrypted key file -- the ciphertext is sensitive)
# ---------------------------------------------------------------------------

_KEYSTORE_CIPHERTEXT_RE = re.compile(r"""["']ciphertext["']\s*:\s*["']([0-9a-fA-F]{32,})["']""")


def detect_keystore(text: str) -> List[Finding]:
    # Only treat a bare "ciphertext" hex as sensitive when the surrounding JSON
    # is clearly a keystore (has a kdf), so we never hit random ciphertext fields.
    low = text.lower()
    if "kdf" not in low:
        return []
    return [
        Finding("KEYSTORE", m.start(1), m.end(1), m.group(1), "high", REDACT, "eth-keystore-v3")
        for m in _KEYSTORE_CIPHERTEXT_RE.finditer(text)
    ]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

DETECTORS = {
    "seed": detect_seeds,
    "hex_keys": detect_hex_keys,
    "wif": detect_wif,
    "xprv": detect_xprv,
    "solana": detect_solana,
    "pem": detect_pem,
    "sui": detect_sui,
    "keystore": detect_keystore,
    "api_keys": detect_api_keys,
    "env": detect_env,
    "otp": detect_otp,
}

_RANK = {"high": 3, "medium": 2, "low": 1}


def _mask_placeholders(text: str) -> str:
    """Replace placeholders with same-length filler so no detector matches them."""
    return PLACEHOLDER_RE.sub(lambda m: "\x00" * len(m.group(0)), text)


def detect_all(text: str, enabled: Optional[Iterable[str]] = None) -> List[Finding]:
    """Run every enabled detector and resolve overlaps.

    Overlap rule: redact beats warn, then higher confidence, then the longer
    span. The result is sorted by start offset and non-overlapping.
    """
    if not text or not isinstance(text, str):
        return []
    scan = _mask_placeholders(text) if "[[sg:" in text else text
    names = list(DETECTORS) if enabled is None else [n for n in DETECTORS if n in set(enabled)]
    raw: List[Finding] = []
    for name in names:
        raw.extend(DETECTORS[name](scan))
    # Values must come from the real text (scan only masks placeholders).
    raw = [Finding(f.kind, f.start, f.end, text[f.start:f.end], f.confidence, f.action, f.detail)
           for f in raw if "\x00" not in scan[f.start:f.end]]

    raw.sort(key=lambda f: (-(f.action == REDACT), -_RANK[f.confidence], -f.length, f.start))
    chosen: List[Finding] = []
    for f in raw:
        if all(f.end <= c.start or f.start >= c.end for c in chosen):
            chosen.append(f)
    chosen.sort(key=lambda f: f.start)
    return chosen
