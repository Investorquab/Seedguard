# Testing

Seedguard is tested in three layers. Claude Code: update the results table
whenever you run the suite on a new Hermes version or OS.

| Layer | What it proves | Command | Needs |
|---|---|---|---|
| Unit | Detectors, the false-positive corpus, the vault, redaction of every request shape, rehydration policy, fail-closed execution, commands, doctor | `pytest -q` | Python 3.10+, pytest |
| In-process integration | Seedguard loads through Hermes' real `PluginManager` and works through the real middleware and hook helpers the agent loop uses | `pytest -q` (runs automatically when `hermes_cli` is importable) | `pip install hermes-agent` |
| End-to-end | Real `hermes chat -q` → Seedguard → `devtools/provider_spy.py`. Asserts no raw secret in any main-loop provider request, and that the terminal tool gets the real value while the model sees only the placeholder | `SEEDGUARD_E2E=1 pytest -q` or `python devtools/e2e_check.py` | `hermes` on PATH |

Test data: public test vectors only (BIP39 and BIP32 vectors, the Bitcoin wiki WIF, Anvil account #0) or random bytes generated at test time.

## Results

| Date | OS | Hermes | Python | Result | Notes |
|---|---|---|---|---|---|
| 2026-11-08 | Linux (cloud sandbox) | 0.19.0 (PyPI) | 3.13 | 77 passed, 1 skipped (+ e2e passed with `SEEDGUARD_E2E=1`) | e2e: main loop clean; tool rehydration OK (66-character key reached the terminal, the model saw a placeholder); aux title call leaks CLI-typed secrets when titles are on (known gap, doctor warns) |
| 2026-11-08 | Windows 10 (Python 3.13.1, isolated `.venv`) | not installed | 3.13 | **121 passed, 2 skipped** | Unit + hardening suite. The 2 skips are the in-process + real-`hermes chat` tests (Hermes not installed on this box). Coverage: detectors 95%, redact 94%, hooks 99%, vault 91% — **total 93%**. Added Sui + keystore detectors, fail-closed/rehydration-security/concurrency/performance tests. 1 MB payload scans in ~1.3 s and is instant on cache repeat. |
| | | latest | | | ← fill in after owner installs Hermes |

## Bugs found by tests (and fixed)

- 2026-11-08: Solana **transaction signatures** (64-byte base58) were redacted as secret keys. Fixed: base58-64B is redacted only with key context, skipped with signature/tx context, and only warns with no context. Covered by `test_solana_signature_not_redacted`.
- 2026-11-08: An OTP code followed by a full stop wasn't detected (`482913.`). Fixed the boundary regex.
- 2026-11-08: Placeholders inside `NAME=[[sg:…]]` were re-matched by the env detector. Fixed overlap filtering.
- 2026-11-08 (e2e): the auxiliary title-generation call bypasses middleware. Documented; doctor added.
- 2026-11-08: `test_doctor_hardened_config` failed on any machine without `hermes-agent` installed, because the environment-driven `middleware` warning was counted as a config warning. Fixed the test to scope its assertion to config checks.
