# Seedguard

**A secret firewall for Hermes Agent. The model never sees your keys; your tools can still use them.**

Paste a seed phrase into Telegram by accident, `cat` a `.env` file, or let the
agent read an email with a 2FA code, and without protection that secret goes
straight to your model provider and stays in your session history. Seedguard
swaps secrets for placeholders like `[[sg:SEED_3fa9c1]]` before anything leaves
your machine. It swaps them back only inside the tools you allow, and only
while you have armed them.

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

## Install

```bash
hermes plugins install Investorquab/Seedguard --enable
# or manually:
git clone https://github.com/Investorquab/Seedguard ~/.hermes/plugins/seedguard
# then add `seedguard` to plugins.enabled in ~/.hermes/config.yaml
```

Then run `/seedguard doctor` once (see "Known limitations").

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

Defaults are safe. To change them, use `~/.hermes/seedguard/config.yaml` or env vars:

```yaml
rehydrate: armed            # never | armed | always
rehydrate_tools: [terminal, execute_code]   # the only tools that can ever get a real value
arm_minutes_default: 10
gateway_inbound: true       # clean chat-app messages before the agent sees them
notify_agent: true          # tell the agent so it warns you to delete the message
detect: {otp: true, seed: true, hex_keys: true, ...}
```

Env overrides: `SEEDGUARD_REHYDRATE`, `SEEDGUARD_REHYDRATE_TOOLS`, `SEEDGUARD_ARM_MINUTES`,
`SEEDGUARD_OTP`, `SEEDGUARD_GATEWAY_INBOUND`.

## How it plugs into Hermes (public surfaces only)

| Surface | Purpose |
|---|---|
| `pre_gateway_dispatch` hook | Rewrite incoming chat messages, so the raw secret never enters the session DB |
| `llm_request` middleware | Redact every provider request; observability plugins see the redacted view |
| `llm_execution` middleware | Enforcement layer. Hermes middleware fails open, so this one never raises: if redaction itself fails it sends a content-free stub instead of your data |
| `tool_request` middleware | Put real values back into args for allowed tools, armed secrets only |
| `pre_tool_call` hook | Block an executing tool that still carries a locked placeholder, and tell the model how the user can release it |
| `transform_terminal_output`, `transform_tool_result` | Re-redact tool output (`cat .env`, email bodies) before it enters context |
| `transform_llm_output` | Last check on the final reply |
| `/seedguard` command | Status, arming, log, doctor |

No core patching, no network, no dependencies beyond the Python standard library.

## Disclosures

- **Files written:** `~/.hermes/seedguard/hmac.key` (32 random bytes, mode 0600, used to derive stable placeholder ids) and `~/.hermes/seedguard/events.jsonl` (kind, placeholder id, location and time of each event; **never secret values**; disable with `log_events: false`).
- **Secret storage:** real values are held **only in process memory** and are gone on restart.
- **Secrets released to tools:** when you arm a secret, or set `rehydrate: always`, the allowed tools (`terminal`, `execute_code` by default) receive the real value. Arming means trusting the agent with that secret for that window. A prompt-injected agent could misuse it, which is why arming is opt-in, time-limited and limited to specific tools.
- **Request rewriting:** Seedguard modifies provider requests, tool arguments, tool results, final replies and inbound chat messages as described above.
- **Config read:** `/seedguard doctor` reads Hermes `config.yaml` read-only.
- **Network / telemetry:** none.
- **Shell commands:** none run by the plugin itself.

## Known limitations (honest list)

Found with the end-to-end test in `devtools/e2e_check.py` against Hermes 0.19:

1. **Auxiliary side-model calls bypass middleware.** Hermes sends some requests to a side model: session titles, context compression, smart approvals. Those don't go through `llm_request`/`llm_execution`. A secret typed into the **CLI** is stored raw in the session, so the title call can still see it. **Secrets sent through a chat app are cleaned before storage and are safe.** `/seedguard doctor` gives the fixes: turn off `auxiliary.title_generation.enabled`, and use `approvals.mode: manual` while secrets are armed.
2. **CLI history keeps raw text.** In the CLI, the raw secret stays in your local session DB. Hermes offers no input-rewrite hook for the CLI. It never reaches the main model.
3. **Armed secrets are visible locally.** An armed secret shows up in the command text of your own approval prompt and in local process arguments.
4. **Ordering with other plugins.** `transform_tool_result` takes the first string returned. If another plugin returns first, our tool-result redaction is skipped, but the provider request is still redacted by middleware.
5. **Heuristics.** Detection relies on patterns. A 64-hex key with no surrounding context only warns, because it looks like a hash. Run `/seedguard test` to check your formats.

## Development

```bash
pip install hermes-agent pytest      # hermes optional: integration tests skip without it
pytest -q                            # unit + in-process Hermes integration tests
SEEDGUARD_E2E=1 pytest -q            # + real `hermes chat` end-to-end via devtools/provider_spy.py
python devtools/provider_spy.py --port 8787                                  # mock provider
python devtools/provider_spy.py --upstream https://openrouter.ai/api/v1      # log a real provider
```

All test keys are public test vectors (BIP39/BIP32 vectors, the Bitcoin wiki WIF, Anvil account #0) or random bytes generated at test time.

MIT licensed.
