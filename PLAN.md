# Seedguard: build plan and status

**Hackathon:** Nous Research Hermes Agent Plugin Hackathon
**Deadline:** Wed **11 Nov 2026, 5:00 PM EST** = 22:00 UTC = **23:00 Lagos (WAT)**
**To enter:** (1) a PR adding `plugin-catalog/seedguard.yaml` to `NousResearch/hermes-agent`, (2) a demo under 90 s posted on X tagging @NousResearch, (3) both links submitted through the form (find the form link in the announcement thread or the Discord).

Owner's other deadlines: Vibeathon 02 on Mon 9 Nov 22:00 UTC, Total Recall on 10 Nov. Seedguard work fits **10 Nov evening → 11 Nov**.

---

## Status at handoff (8 Nov 2026)

### Done and tested

- [x] Detectors: BIP39 with checksum; EVM/hex keys with context; WIF; xprv; Solana base58 and JSON keypairs; PEM; 10 API-key families plus Bearer; `.env`/JSON secrets; OTP codes (`detectors.py`)
- [x] In-memory vault with HMAC-stable placeholder ids, arm/disarm/forget, and an event log that never stores values (`vault.py`)
- [x] Redaction of nested provider requests (OpenAI chat, Responses, Anthropic shapes). Auth headers, tool schemas and ids are skipped (`redact.py`)
- [x] Fail-closed `llm_execution` layer that sends a content-free stub if redaction errors (`hooks.py`)
- [x] Rehydration into allowed tools only, armed only, time-limited; `pre_tool_call` explains how to unlock
- [x] Redaction of terminal output, tool results, final replies and inbound gateway messages, with a notice asking the agent to tell the user to delete their message
- [x] `/seedguard` status | arm | disarm | forget | log | test | doctor (`commands.py`, `doctor.py`)
- [x] `plugin.yaml`
- [x] **77 tests pass, plus 1 opt-in e2e:**
  - unit tests
  - in-process integration: Seedguard loaded by the real Hermes 0.19 `PluginManager`, with real middleware and hook helpers
  - **real `hermes chat -q` end-to-end** against `devtools/provider_spy.py`
- [x] `devtools/provider_spy.py`: a mock or logging-proxy provider that shows exactly what the model receives. This is also the demo prop.
- [x] `devtools/demo_setup.py` (isolated demo home), `.github/workflows/tests.yml` (CI), false-positive corpus, NEAR `ed25519:` keys, and a fix so Solana tx signatures aren't redacted
- [x] Beginner docs: START_HERE.md, KICKOFF_PROMPT.md, TASKS.md, TESTING.md; CLAUDE.md is now the full autonomous playbook

### End-to-end findings (Hermes 0.19, from PyPI)

| Request | Result |
|---|---|
| main agent loop | ✔ clean: only placeholders reach the provider |
| tool rehydration | ✔ terminal got the real key (output `key-length: 66`); the model only saw `[[sg:EVM_KEY_…]]` |
| auxiliary **title generation** | ✘ **leaks** a secret typed in the CLI. Aux calls don't go through middleware. The chat-app path is clean because `pre_gateway_dispatch` rewrites before storage. |

---

## Remaining work: in priority order

### P0: must do before submitting (about 6–8 h)

1. **Create the GitHub repo** `seedguard` (public, MIT). The repo root is the plugin root, as in this zip. Replace every `REPLACE_ME` (`README.md`, `plugin.yaml`, `catalog/seedguard.yaml`).
2. **Test on the latest Hermes.** The PyPI build is 0.19; current is about 0.23. Install from source (`pip install git+https://github.com/NousResearch/hermes-agent` or `hermes update`), then:
   - `hermes plugins validate . --install-deps --ci` and `hermes plugins doctor .`. Fix whatever they flag. Watch whether `provides_middleware` belongs in `plugin.yaml` or only in the catalog `capabilities` block, and whether the manifest v2 fields are accepted.
   - Re-run `pytest -q` and `SEEDGUARD_E2E=1 pytest -q`.
   - If the security scan flags `devtools/` (urllib network and subprocess in the spy and e2e harness) or `tests/`, move the plugin files into a `plugin/` subfolder and set `subdir: plugin` in the catalog entry. That keeps dev tools out of what users install.
   - **Check auxiliary calls on the latest version.** `grep -rn "apply_llm_request_middleware\|pre_auxiliary_call" agent/auxiliary_client.py`. If the latest Hermes sends aux calls through middleware, or has a modifying `pre_auxiliary_call`, register it and turn the title leak into a pass. If it doesn't, keep the doctor warning and the README limitation. Optionally open an issue asking for the seam; the catalog README says Nous prefers that over patches.
3. **Pin the catalog entry.** Commit, copy the 40-character SHA into `catalog/seedguard.yaml`, then open the PR adding `plugin-catalog/seedguard.yaml`. Use the PR body in `SUBMISSION.md`.
4. **Record the demo** (`DEMO.md`). Post it on X tagging @NousResearch, then submit both links on the form.

### P1: strong stretch goals (pick by time left)

5. **Desktop pane "What the model saw"** (`desktop/plugin.js`). A pane plus status-bar chip listing caught secrets (kind, placeholder, armed timer) with Arm/Disarm buttons. It reads `~/.hermes/seedguard/events.jsonl` or a gateway RPC. Desktop SDK: <https://hermes-agent.nousresearch.com/docs/developer-guide/desktop-plugin-sdk>. Rules:
   - single ESM file, no build step, no JSX (use `jsx()` from `react/jsx-runtime`)
   - imports only from `@hermes/plugin-sdk`, `react` and `react/jsx-runtime`
   - the folder name must match `id`
   - a unified package ships it at `desktop/plugin.js`

   Judges score UI visibly (screenshots go in the PR), so this is the biggest polish win.
6. **Env-style rehydration** (`rehydrate_style: env`). Instead of putting the value into the command text, rewrite `[[sg:EVM_KEY_x]]` to `"$SGV_x"`. A `tool_execution` middleware sets `os.environ["SGV_x"]` just around `next_call` and removes it afterwards. The approval prompt, the smart-approval side model and the session log then show `$SGV_x` instead of the value.
   - Keep the name free of `KEY`/`SECRET`/`TOKEN`: `execute_code` strips those.
   - This only works for local backends; fall back to inline for docker/ssh/modal.
   - Add tests.
7. **More chains:** Sui `suiprivkey1…` (bech32), NEAR `ed25519:` (done), Cosmos mnemonic (same BIP39), Aptos (hex plus context, already covered), Tron (hex).

### P2: nice to have

8. `/seedguard allow <tool>` to edit `rehydrate_tools` at runtime.
9. Per-platform policy, for example never rehydrate in group chats.
10. Count warnings for bare hex in `/seedguard status`, with a "show me" via `/seedguard log`.

---

## Timeline to the deadline (WAT)

| When | What |
|---|---|
| Tue 10 Nov evening (2–3 h) | P0.1–P0.2: repo, latest Hermes, validate, fix |
| Wed 11 Nov morning (3 h) | P1.5 Desktop pane, or P1.6 env rehydration if the Desktop SDK fights back |
| Wed 11 Nov 14:00 | Feature freeze. Screenshots, pin SHA, open catalog PR |
| Wed 11 Nov 16:00 | Record and edit the 90 s demo, post on X |
| Wed 11 Nov 18:00 | Submit the form. **Hard stop 22:00 WAT**; the real deadline is 23:00 WAT |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Someone already built a redaction plugin | First: run `hermes plugins search secret`, `redact`, `seed`, `pii`, and skim open `plugin-catalog` PRs. Our angle is placeholder + armed rehydration, crypto-grade detectors, a fail-closed layer, and a provider spy that proves it. |
| Latest Hermes changed hook or middleware signatures | All callbacks take `**kwargs`. The integration test catches drift; run it on the latest version first (P0.2). |
| False positives annoy users | Context rules for hex; checksum for seeds; detectors can be switched off; `/seedguard test` |
| Judges ask "does it really stop leaks?" | provider_spy on screen in the demo; e2e test in CI; honest limitations in the README |
| The catalog PR isn't merged by judging time | Rules only ask to *open* the PR (unverified). Make CI pass and disclose everything so it's merge-ready. |
