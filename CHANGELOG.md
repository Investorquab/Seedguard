# Changelog

All notable changes to Seedguard are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.1.1] — 2026-11-09

Fixes from the Nous Research catalog review of `f61f05fe`.

### Fixed

- **Plugin settings now apply.** `ctx.get_config` is read one key at a time
  (`get_config(key, default)`), not called with no key — the old keyless call
  raised a swallowed `TypeError`, so `plugins.entries.seedguard.settings` and the
  `config_schema` never took effect (e.g. `rehydrate: never` was ignored). Also
  dropped the optional `seedguard/config.yaml` route, which imported a non-core
  `yaml` and was silently skipped on a stock install; configuration is now Hermes
  plugin settings plus `SEEDGUARD_*` env vars only (still standard-library only).
- **Secrets are scoped per conversation.** The vault was process-wide, so on a
  multi-user gateway `/seedguard status` listed every chat's secrets, `arm all`
  armed them all, and a tool call in chat B carrying chat A's placeholder got
  A's real value. Entries are now keyed by `session_id`; `status|arm|disarm|forget`
  act only on the calling chat, and a placeholder only resolves in the session
  that caught it.
- **Bounded the `NAME=value` detector regex.** `_SECRET_NAME` had two unbounded
  `[A-Za-z0-9_]*` runs around the keyword group — quadratic on a long unbroken
  token, which could stall every tool-result hook on tens of KB. Both runs are
  now bounded to `{0,64}`.

### Added

- Per-session entry cap (256, oldest evicted) so an unadmitted sender cannot pin
  unbounded memory before auth.
- Tests: per-session isolation (`tests/test_sessions.py`), plugin-settings
  loading (`tests/test_config.py`), and regex timing on a 50 KB token
  (`tests/test_perf_regex.py`).

## [0.1.0] — 2026-11-08

First public release: a secret firewall for Hermes Agent. The model never sees
your keys; your tools can still use them.

### Added

- **Detectors** (standard-library only, pure functions): BIP39 seed phrases
  (checksum-verified), EVM / raw 32-byte hex keys (context-gated), Bitcoin WIF
  and BIP32 extended private keys (base58check), Solana / NEAR secret keys
  (64-byte base58, signature-aware), Sui private keys (`suiprivkey1…`, bech32
  checksum-verified), Ethereum V3 keystore JSON ciphertext, Aptos / Tron hex
  keys (context-gated), PEM private keys, provider / platform API keys
  (OpenAI, Anthropic, OpenRouter, GitHub, AWS, Slack, Stripe, Google, Telegram,
  Hugging Face, Bearer), `.env` / JSON `NAME=value` secrets, and one-time codes.
- **Vault**: in-memory secrets with HMAC-derived stable placeholder ids; arm /
  disarm / forget; an event log that records kind, id, location and time —
  never values.
- **Redaction engine**: redact text and nested provider-request objects;
  rehydrate tool arguments under policy; an LRU cache; a content-free stub
  request for the fail-closed path.
- **Hermes integration** (public surfaces only): `pre_gateway_dispatch`,
  `llm_request`, `llm_execution` (fail-closed), `tool_request`, `pre_tool_call`,
  `transform_terminal_output`, `transform_tool_result`, `transform_llm_output`,
  and the `/seedguard` command.
- **`/seedguard doctor`**: reports the auxiliary-call paths Seedguard cannot
  cover and the exact config fixes.
- **Dev tools**: provider spy (mock / logging proxy), real `hermes chat` e2e
  harness, and an isolated demo-home builder.
- **Tests**: 121 passing (plus 2 Hermes-only tests skipped without Hermes),
  covering detectors, a false-positive corpus, fail-closed enforcement,
  rehydration security, concurrency and performance. Core-module coverage ≥ 90 %
  (detectors 95 %, redact 94 %, hooks 99 %, vault 91 %).

### Known limitations

- Auxiliary side-model calls (session titles, context compression, smart
  approvals) bypass middleware in Hermes 0.19; a secret typed into the CLI can
  reach them. Chat-app input is cleaned before storage. `/seedguard doctor`
  gives the config fixes. See README "Known limitations".
