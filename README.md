# Seedguard

> **A secret firewall for Hermes Agent. The model never sees your keys; your tools can still use them.**

[![Tests](https://github.com/Investorquab/Seedguard/actions/workflows/tests.yml/badge.svg)](https://github.com/Investorquab/Seedguard/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Hermes](https://img.shields.io/badge/Hermes-%E2%89%A50.19-FFB020)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-0-success)
![Fail-closed](https://img.shields.io/badge/enforcement-fail--closed-critical)

Paste a seed phrase into Telegram by accident, `cat` a `.env` file, or let the
agent read an email with a 2FA code, and without protection that secret goes
straight to your model provider and stays in your session history. Seedguard
swaps secrets for placeholders like `[[sg:SEED_3fa9c1]]` before anything leaves
your machine. It swaps them back only inside the tools you allow, and only
while you have armed them.

![Seedguard in a live Hermes session: the model replies that it only sees the placeholder `[[sg:SEED_77a6c6]]`, not the seed words, and a private-key tool call is blocked until the user arms it.](assets/seedguard-redaction.png)

*A real Hermes 0.23 session: the agent is handed a seed phrase and a private key (public test vectors), and tells you itself that it only ever saw placeholders. The tool call is blocked until you `/seedguard arm` it.*

## Contents

[Security model](#security-model) · [How it works](#how-it-works) · [What it catches](#what-it-catches) · [Quick start](#quick-start) · [Commands](#commands) · [Configuration](#configuration) · [Hermes surfaces](#how-it-plugs-into-hermes-public-surfaces-only) · [Testing & quality](#testing--quality) · [Compatibility](#compatibility) · [Disclosures](#disclosures) · [Known limitations](#known-limitations-honest-list) · [Development](#development)

## Security model

Seedguard defends **one boundary**: the line between your machine and the model
provider. It is defense-in-depth across the whole request lifecycle, and it is
honest about what it does not cover.

**What it guarantees**

- **Nothing in a detected secret format reaches the model through the main loop.**
  Every provider request is redacted at `llm_request` and re-checked at
  `llm_execution`. That enforcement layer is **fail-closed**: if redaction itself
  ever errors, it sends a content-free stub instead of your data, so a bug in
  Seedguard can never *leak* a secret — at worst it withholds a request.
- **A real value reaches a tool only under an explicit, narrow grant.** All three
  must hold: the tool is on the allowlist (`terminal`, `execute_code` by default),
  the secret is *armed* (or `rehydrate: always`), and rehydration is enabled.
  Otherwise the tool call is **blocked** and the model is told how to ask you to
  release it.
- **Secrets are never written to disk by Seedguard.** Real values live only in
  process memory and are gone on restart. The event log records *kind, placeholder
  id, where and when* — never values.
- **Secrets can't leak back in through tool output.** A dumped `.env` file, email
  bodies and other tool results are re-scanned before they re-enter the model's context.

**What it is not** (threat boundaries, stated plainly)

- Not a reason to paste real secrets. Prefer test keys; Seedguard is a safety net,
  not a license to be careless.
- Detection is heuristic. An unknown secret format, or a bare 64-hex string with no
  surrounding context, may only be *warned* rather than redacted. Use
  `/seedguard test <text>` to see exactly what the model would receive.
- Arming is a deliberate, time-boxed grant of trust. While a secret is armed, a
  prompt-injected agent *can* use it — but only inside the allowed tool, for the
  window you set. That is the trade-off that makes tools usable at all.
- It protects the model boundary, not your local host. An armed value still appears
  in local process arguments and in your own approval prompt.
- Hermes' auxiliary side-model calls (titles, compression) bypass plugin middleware
  — see [Known limitations](#known-limitations-honest-list); `/seedguard doctor`
  prints the exact config fixes.

## How it works

```
you (Telegram) ──► "my seed is abandon abandon … about"
                    │  pre_gateway_dispatch: redacted before the agent sees it
agent / history ──► "my seed is [[sg:SEED_2b8b06]]"
                    │  llm_request + llm_execution: every provider request re-checked
model provider  ──► "my seed is [[sg:SEED_2b8b06]]"   ✔ never the real words
                    │
model asks for  ──► terminal: cast wallet address --private-key [[sg:EVM_KEY_cf547c]]
                    │  tool_request: released only if you ran /seedguard arm EVM_KEY_cf547c
terminal runs   ──► … --private-key 0xac09…ff80   (real value, local only)
                    │  transform_terminal_output: output re-redacted
model sees      ──► the result, with secrets still masked
```

## What it catches

| Kind | How it's recognised | Confidence |
|---|---|---|
| BIP39 seed phrases (12–24 words) | Official 2048-word list **plus checksum**; handles numbering, commas, line breaks, uppercase | high (medium if right length, bad checksum) |
| EVM / raw 32-byte hex keys | 64 hex characters **with key context** ("private key", `PRIVATE_KEY=`…). Transaction hashes stay readable | high; bare hex with no context only warns |
| Bitcoin WIF, BIP32 `xprv/tprv/zprv` | base58check verified | high |
| Solana / NEAR secret keys | base58 that decodes to exactly 64 bytes **with key context** (transaction signatures have the same shape and are left alone); NEAR `ed25519:` secret keys; `id.json` 64-number arrays | high; no context only warns |
| Sui private keys | `suiprivkey1…` **bech32 checksum verified** | high |
| Ethereum V3 keystore JSON | the `ciphertext` of an encrypted keystore (detected by its `kdf`/`crypto` structure) | high |
| Aptos / Tron keys | 64-hex **with key context** (handled by the context-hex detector) | high; no context only warns |
| PEM private keys | `-----BEGIN … PRIVATE KEY-----` blocks, including escaped `\n` inside JSON | high |
| Provider / platform API keys | OpenAI, Anthropic, OpenRouter, GitHub, AWS, Slack, Stripe, Google, Telegram bot, Hugging Face, `Bearer …` | high |
| `.env` / JSON secrets | `NAME=value` and `"name": "value"` where the name says KEY/SECRET/TOKEN/PASSWORD/PRIVATE/MNEMONIC/SEED | high |
| One-time codes | 4–8 digits near "verification code", "OTP", "2FA"… (skips status codes, ports, years) | medium |

Verifiable formats (BIP39, WIF, xprv, Sui) are checksum-validated, so they are
redacted with confidence. Ambiguous formats are context-gated to avoid breaking
real crypto workflows — a transaction hash or public address is left readable.

## Quick start

```bash
hermes plugins install Investorquab/Seedguard --enable
# or manually:
git clone https://github.com/Investorquab/Seedguard ~/.hermes/plugins/seedguard
# then add `seedguard` to plugins.enabled in ~/.hermes/config.yaml
```

Run `/seedguard doctor` once after installing — it reports the paths Seedguard
can't cover in your current Hermes config and prints the one-line fixes.

A typical session:

```text
you    ▸ my private key is 0x… , what's its address? use the terminal
hermes ▸ That placeholder is locked — run  /seedguard arm EVM_KEY_0166d0
you    ▸ /seedguard arm EVM_KEY_0166d0 5
hermes ▸ (terminal runs with the real key) the address is 0xf39F…2266
         I only ever saw the placeholder.
```

## Commands

```
/seedguard                    status: protected secrets (kind, placeholder, armed), never values
/seedguard arm <id|all> [min] let allowed tools use a secret for N minutes (default 10)
/seedguard disarm [id|all]    lock again
/seedguard forget [id|all]    drop from memory (placeholders stop resolving)
/seedguard log [n]            recent events: what was caught or released, and where (never values)
/seedguard test <text>        preview what the model would see
/seedguard doctor             paths Seedguard can't cover in your config, with fixes
```

## Configuration

Defaults are safe. To change them, set Hermes plugin settings (read through
`ctx.get_config`, one key at a time) in your Hermes config, under
`plugins.entries.seedguard.settings`:

```yaml
plugins:
  entries:
    seedguard:
      settings:
        rehydrate: armed            # never | armed | always
        rehydrate_tools: [terminal, execute_code]   # the only tools that can ever get a real value
        arm_minutes_default: 10
        gateway_inbound: true       # clean chat-app messages before the agent sees them
        notify_agent: true          # tell the agent so it warns you to delete the message
        detect: {otp: true, seed: true, hex_keys: true}   # per-detector switches
```

Env overrides (highest precedence, no Hermes config needed): `SEEDGUARD_REHYDRATE`,
`SEEDGUARD_REHYDRATE_TOOLS`, `SEEDGUARD_ARM_MINUTES`, `SEEDGUARD_OTP`, `SEEDGUARD_GATEWAY_INBOUND`.

Seedguard keeps no config file of its own, so it pulls in no YAML parser at
runtime (standard library only).

## How it plugs into Hermes (public surfaces only)

| Surface | Purpose |
|---|---|
| `pre_gateway_dispatch` hook | Rewrite incoming chat messages, so the raw secret never enters the session DB |
| `llm_request` middleware | Redact every provider request; observability plugins see the redacted view |
| `llm_execution` middleware | Enforcement layer. Hermes middleware fails open, so this one never raises: if redaction itself fails it sends a content-free stub instead of your data |
| `tool_request` middleware | Put real values back into args for allowed tools, armed secrets only |
| `pre_tool_call` hook | Block an executing tool that still carries a locked placeholder, and tell the model how the user can release it |
| `transform_terminal_output`, `transform_tool_result` | Re-redact secrets in tool output (a dumped `.env` file, email bodies) before it enters context |
| `transform_llm_output` | Last check on the final reply |
| `/seedguard` command | Status, arming, log, doctor |

No core patching, no network, no dependencies beyond the Python standard library.

## Testing & quality

- **129 tests** (unit, false-positive corpora, fail-closed enforcement, rehydration
  security, concurrency and performance), plus 2 opt-in Hermes tests.
- **Core-module coverage ~93%** (`detectors` 95%, `redact` 94%, `hooks` 99%, `vault` 91%).
- **Validated on the latest Hermes (0.23)**: `hermes plugins validate --install-deps`
  and `hermes plugins doctor` both pass; install **security scan is clean**; declared
  capabilities match what the plugin registers.
- **CI** runs the unit + in-process Hermes integration suites on Python 3.10–3.13.
- All test material is **public test vectors** (BIP39/BIP32 vectors, the Bitcoin wiki
  WIF, Anvil account #0) or random bytes generated at test time — never a real key.

See [TESTING.md](TESTING.md) for the test matrix and how to run each layer.

## Compatibility

- **Hermes Agent ≥ 0.19** (verified on 0.19 and 0.23). Older releases without the
  middleware API load Seedguard in a degraded, hooks-only mode and `/seedguard doctor`
  warns you.
- **Python 3.10+**. Standard library only at runtime; `pytest` is a dev/test dependency.
- Cross-platform (Linux, macOS, Windows).

## Disclosures

- **Files written:** under Hermes' per-plugin data dir `~/.hermes/plugin-data/seedguard/` (via the documented `plugins.plugin_storage.plugin_data_dir`, which survives `hermes plugins update`/`remove`; falls back to `~/.hermes/seedguard/` on older Hermes): `hmac.key` (32 random bytes, mode 0600, used to derive stable placeholder ids) and `events.jsonl` (kind, placeholder id, location and time of each event; **never secret values**; disable with `log_events: false`).
- **Secret storage:** real values are held **only in process memory** and are gone on restart. They are **scoped per chat**: the vault is keyed by a chat identity that every layer computes the same way — from `event.source` on the inbound hook, from `gateway.session_context.get_session_env("HERMES_SESSION_PLATFORM" / "…CHAT_ID" / "…THREAD_ID" / "…USER_ID")` on the request/tool/output paths, and from the `source` the slash command is handed. So a secret caught in one chat is only visible to `/seedguard status|arm|disarm|forget` from that same chat, and a placeholder that leaks into another chat never resolves there. Off a gateway (the CLI/TUI/desktop) there is a single local session. A gateway message or command whose chat can't be identified is refused, never folded into a shared bucket. Each chat holds at most 256 distinct secrets (oldest evicted past that), so an unauthenticated sender cannot pin unbounded memory.
- **Secrets released to tools:** when you arm a secret, or set `rehydrate: always`, the allowed tools (`terminal`, `execute_code` by default) receive the real value. Arming means trusting the agent with that secret for that window. A prompt-injected agent could misuse it, which is why arming is opt-in, time-limited and limited to specific tools.
- **Request rewriting:** Seedguard modifies provider requests, tool arguments, tool results, final replies and inbound chat messages as described above.
- **Config read:** `/seedguard doctor` reads Hermes `config.yaml` read-only.
- **Network / telemetry:** none.
- **Shell commands:** none run by the plugin itself.

## Known limitations (honest list)

Found with the end-to-end test in `devtools/e2e_check.py` and verified against Hermes 0.19 and 0.23:

1. **Auxiliary side-model calls bypass middleware.** Hermes sends some requests to a side model: session titles, context compression, smart approvals. Those don't go through `llm_request`/`llm_execution`. A secret typed into the **CLI** is stored raw in the session, so the title call can still see it. **Secrets sent through a chat app are cleaned before storage and are safe.** `/seedguard doctor` gives the fixes: turn off `auxiliary.title_generation.enabled`, and use `approvals.mode: manual` while secrets are armed. *Confirmed on Hermes 0.23:* it adds `pre_auxiliary_call` / `post_auxiliary_call` events, but they are **observer-only** (they carry metrics, not the request body, and their return value is ignored), so they cannot redact the call — the config fixes above remain the mitigation.
2. **CLI history keeps raw text.** In the CLI, the raw secret stays in your local session DB. Hermes offers no input-rewrite hook for the CLI. It never reaches the main model.
3. **Armed secrets are visible locally.** An armed secret shows up in the command text of your own approval prompt and in local process arguments.
4. **Ordering with other plugins.** `transform_tool_result` takes the first string returned. If another plugin returns first, our tool-result redaction is skipped, but the provider request is still redacted by middleware.
5. **Heuristics.** Detection relies on patterns. A 64-hex key with no surrounding context only warns, because it looks like a hash. Run `/seedguard test` to check your formats.
6. **Encoded or split secrets.** Because detection is pattern-based, a secret that is base64/hex-encoded, compressed, or split across two *separate* tool outputs or streaming chunks can pass the detectors — each fragment on its own doesn't look like a key. The model still only ever sees placeholders for what *is* caught, and if redaction itself ever errors the fail-closed `llm_execution` layer sends a content-free stub, so a detection miss doesn't become an unbounded leak — but an obfuscated secret in the input is a real gap. (Characterized in `tests/test_resolution_boundary.py`.)
7. **Logs outside the model's context.** Seedguard redacts tool output, terminal output and provider requests as they enter the model's context, but it does not control Hermes' own internal/debug logs, nor anything a tool writes straight to disk or to a file descriptor Seedguard doesn't sit on.

**Not a permission boundary.** Redaction reduces *exposure* to the model and the provider; it is not an authorization layer. Sensitive actions still go through Hermes' own approval/permission gates — rehydration happens in `tool_request` *before* that gate, so your approvals apply on top of Seedguard rather than being replaced by it. Only `tool_request` ever turns a placeholder back into a value; no other hook resolves one (pinned in `tests/test_resolution_boundary.py`).

## Development

```bash
pip install hermes-agent pytest      # hermes optional: integration tests skip without it
pytest -q                            # unit + in-process Hermes integration tests
SEEDGUARD_E2E=1 pytest -q            # + real `hermes chat` end-to-end via devtools/provider_spy.py
python devtools/provider_spy.py --port 8787                                  # mock provider
python devtools/provider_spy.py --upstream https://openrouter.ai/api/v1      # log a real provider
```

All test keys are public test vectors (BIP39/BIP32 vectors, the Bitcoin wiki WIF, Anvil account #0) or random bytes generated at test time.

## License

[MIT](LICENSE) © the Seedguard authors. Contributions and issues welcome on
[GitHub](https://github.com/Investorquab/Seedguard).
