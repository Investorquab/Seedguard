"""Known-good test vectors. NONE of these control real funds: they are the
public test vectors from BIP39 / BIP32 / the Bitcoin wiki, or random bytes
generated at test time."""

# BIP39 official test vectors (all-zero entropy)
SEED_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SEED_24 = " ".join(["abandon"] * 23 + ["art"])
# Right length, wrong checksum
SEED_12_BAD = " ".join(["abandon"] * 12)

# Bitcoin wiki WIF example (uncompressed, mainnet)
WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

# BIP32 test vector 1, master xprv
XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

# Hardhat / Anvil default account #0 private key (public knowledge, test-only)
EVM_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

TX_HASH = "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"


# -- Sui private key (Bech32 "suiprivkey1...") -------------------------------
# Built at test time from random bytes so no real key is ever hard-coded.
from seedguard.detectors import (  # noqa: E402
    _BECH32_CHARSET, _bech32_hrp_expand, _bech32_polymod,
)


def _convertbits(data, frm, to, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    return ret


def make_suiprivkey(seed32: bytes) -> str:
    """Encode 32 secret bytes as a valid, checksummed suiprivkey (ed25519 flag)."""
    hrp = "suiprivkey"
    data5 = _convertbits(b"\x00" + seed32, 8, 5)
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data5 + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data5 + chk)


# A real-looking V3 keystore (random ciphertext; decrypts to nothing).
def make_keystore(ciphertext_hex: str) -> str:
    return (
        '{"version":3,"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","address":"008aeeda4d805471df9b2a5b0f38a0c3bcba786b",'
        '"crypto":{"ciphertext":"%s","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},'
        '"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"r":8,"p":1,'
        '"salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},'
        '"mac":"517ead924a9d0dc3124507c3393d175e3f5a4d3014bc87c060ac9d6a687f0e30"}}' % ciphertext_hex
    )
