# Changelog

All notable changes to Seedguard are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.1.2] — 2026-11-10

Fixes from the second Nous Research catalog review (delta from `28c7a8dc`).

### Fixed

- **Vault is now keyed by chat identity, not a shared `"local"` bucket.** The old
  `session_of` looked for `session_id`/`chat_id` on the gateway `MessageEvent` and
  on `transform_terminal_output`, but a `MessageEvent` carries neither (the chat id
  is on `event.source`), so every gateway inbound catch and every terminal-output
  catch fell into one shared bucket. Effect: a secret pasted in a chat could never
  be armed from that chat (the README's headline flow), and `/seedguard status` /
  `forget all` in a chat with no stored session listed or wiped *every other* chat's
  catches. No real secret values leaked. The vault is now keyed by a chat identity
  every layer computes the same way — from `event.source` on `pre_gateway_dispatch`,
  from `gateway.session_context.get_session_env("HERMES_SESSION_PLATFORM" /
  "…CHAT_ID" / "…THREAD_ID" / "…USER_ID")` on the request/tool/output paths, and from
  the `source` the slash command is handed. Off a gateway (CLI/TUI/desktop) there is
  a single local session; a gateway message or command whose chat can't be
  identified is refused, never folded into a shared bucket. For a shared (non-DM)
  chat the inbound/command key mirrors Hermes' own `session_env_source` normalization
  (which drops the user from the turn-path route in e.g. Telegram observe mode), so a
  secret armed in a group is still released to its tools there.
  (+`tests/test_sessions.py`, now exercising the real `MessageEvent`/`SessionSource`
  shape instead of a fabricated `event.session_id`, incl. inbound==command==turn key
  parity in DMs and shared chats.)

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

### Changed

- **State lives under Hermes' per-plugin data dir.** `hmac.key` and
  `events.jsonl` now go to `<hermes home>/plugin-data/seedguard/` via the
  documented `plugins.plugin_storage.plugin_data_dir` helper (survives
  `hermes plugins update`/`remove`, follows the active profile), falling back to
  the old `<hermes home>/seedguard/` when that helper isn't available.

### Added

- Per-session entry cap (256, oldest evicted) so an unadmitted sender cannot pin
  unbounded memory before auth.
- Tests: per-session isolation (`tests/test_sessions.py`), plugin-settings
  loading (`tests/test_config.py`), regex timing on a 50 KB token
  (`tests/test_perf_regex.py`), state-dir selection (`tests/test_state_dir.py`),
  and the resolution boundary + detection gaps (`tests/test_resolution_boundary.py`:
  only `tool_request` rehydrates; encoded / split-across-output secrets are
  characterized as known gaps).
- Disclosures: "Known limitations" now spells out encoded/split secrets, the
  scope of logs, and that redaction is not a permission boundary (approvals run
  on top, in Hermes' own gate).

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
