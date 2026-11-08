"""Things an agent sees every day that must NOT be redacted.

Every time a false positive is found in the wild, add the text here.
"""

import os

import pytest

from seedguard import detectors as d
from seedguard.detectors import REDACT, detect_all

SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

BENIGN = {
    "pip_hashes": f"Collecting requests==2.32.3\n  Downloading requests-2.32.3-py3-none-any.whl --hash=sha256:{SHA}",
    "docker_digest": f"Digest: sha256:{SHA}\nStatus: Downloaded newer image for python:3.12",
    "git_log": "commit 3f1c2a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a\nAuthor: dev <dev@example.com>\n\n    fix: handle tokens",
    "eth_address": "Send 0.5 ETH to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e on Base",
    "eth_tx": "tx 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060 was mined in block 19000000",
    "eth_tx_url": "https://basescan.org/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
    "btc_address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq and 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "ipfs_cid": "pinned at ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
    "uuid": "request id 123e4567-e89b-12d3-a456-426614174000",
    "http_logs": "GET /api/v1/users 200 in 1234ms\nPOST /login 401 port 8080 error code 4031",
    "code_tokens": "def count_tokens(text):\n    max_tokens = 4096\n    token_count = len(text) // 4\n    return token_count",
    "config_doc": "Set OPENAI_API_KEY=<your key here> and ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}",
    "prose_crypto": ("A seed phrase is twelve or twenty-four words. Never share your private key. "
                     "The wallet derives addresses from the mnemonic using BIP32."),
    "prose_story": ("The old man walked along the river every morning before the market opened, "
                    "carrying a basket of bread for the birds that waited near the bridge"),
    "dates_numbers": "Invoice 2024-11-08, order 558812, total $1299.00, call +1 555 0100, zip 94107",
    "phone_otp_like_not": "The meeting is at 1430 in room 2201, see you on floor 12",
    "base64_image": "data:image/png;base64," + "iVBORw0KGgo" * 200,
    "jwt_shape_header_only": "Authorization header format is: Bearer <token>",
    "sol_address": "Fee payer: 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    "npm_log": ("added 212 packages in 4s\nnpm warn deprecated har-validator@5.1.5\n"
                "integrity sha512-ABCdef0123456789ghIJKLmnopQRstuvWXyz/+abcdef0123456789ABCDEF=="),
    "cargo_log": ("Compiling serde v1.0.210\n   Compiling tokio v1.40.0\n"
                  "    Finished release [optimized] target(s) in 1m 03s\n  Fingerprint: 3f1c2a9b8d7e6f5a"),
    "github_api_json": ('{"sha": "3f1c2a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2", "node_id": "C_kwDOABCD", '
                        '"commit": {"message": "fix: handle tokens", "comment_count": 0}}'),
    # A bare JWT in a log line (no secret-named assignment) must not be redacted.
    "jwt_full": ("Decoded JWT header.payload.signature: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                 "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                 "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    "solscan_page": ("Signature 5VfY...  Status: Success  Block: 254318991  "
                     "https://solscan.io/tx/4pXnqUoy3x9vJ8WTc5V2bRk8fZ1aXmL9nQpWdeRtYuIoPaSdFgHjKlZxCvBnM"),
    "near_pubkey": "account alice.near public key ed25519:H9k5eiU4xXS3M4z8kzjx2x9VnSsx5R6y7zQ3bQ2aBcDe",
    "markdown_table": ("| metric | q1 | q2 | q3 |\n|---|---|---|---|\n"
                       "| revenue | 12400 | 13820 | 15190 |\n| users | 48213 | 51902 | 56104 |"),
    "eth_keystore_address_field": ('{"address": "008aeeda4d805471df9b2a5b0f38a0c3bcba786b", '
                                   '"id": "3198bc9c-6672-5ab3-d995-4942343ae5b6", "version": 3}'),
}


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_text_not_redacted(name):
    redacted = [f for f in detect_all(BENIGN[name]) if f.action == REDACT]
    assert redacted == [], f"{name}: {[(f.kind, f.detail) for f in redacted]}"


def test_large_request_is_fast():
    import time

    blob = (BENIGN["prose_story"] + "\n" + BENIGN["git_log"] + "\n") * 2000  # ~600 KB
    t = time.perf_counter()
    detect_all(blob)
    assert time.perf_counter() - t < 5.0


def test_many_random_base58_strings_never_redacted_without_context():
    for _ in range(50):
        s = d.b58encode(os.urandom(64))
        assert [f for f in detect_all(f"value {s}") if f.action == REDACT] == []
