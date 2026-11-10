"""The ``/seedguard`` slash command (CLI and every gateway).

Subcommands
-----------
/seedguard                    same as status
/seedguard status             protected secrets (kind, placeholder, armed) -- never values
/seedguard arm <id|all> [min] let allowed tools use a secret for N minutes
/seedguard disarm [id|all]    lock again
/seedguard forget [id|all]    drop from memory (placeholders stop resolving)
/seedguard log [n]            recent events (where/what, never values)
/seedguard test <text>        show how text would be redacted
/seedguard doctor             paths Seedguard can't cover in your config, with fixes
/seedguard help
"""

from __future__ import annotations

import time
from typing import Any

from .hooks import NO_SESSION, Runtime, session_of

HELP = __doc__.split("Subcommands", 1)[1].split("\n", 2)[2].rstrip()


def _fmt_age(ts: float) -> str:
    secs = int(time.time() - ts)
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    return f"{secs // 3600}h ago"


def make_handler(rt: Runtime):
    def handler(raw_args: Any = "", *_: Any, **kwargs: Any) -> str:
        args = (raw_args or "").strip().split()
        sub = args[0].lower() if args else "status"
        rest = args[1:]
        # Act only on the chat that ran the command: on a multi-user gateway
        # /seedguard status|arm|disarm|forget must not reach another chat's secrets.
        # Core passes a SessionSource as ``source`` on a gateway (None on the CLI).
        session = session_of(kwargs, command=True)

        if sub in ("help", "-h", "--help"):
            return "Seedguard commands:\n" + HELP

        if sub == "doctor":
            from .doctor import format_report, run_checks

            return format_report(run_checks(rt))

        # A gateway chat we could not identify: refuse rather than read or wipe
        # another conversation's secrets out of a shared bucket.
        if session == NO_SESSION and sub in ("status", "arm", "disarm", "forget"):
            return ("Seedguard: no session. I couldn't identify this chat, so I won't "
                    "touch another conversation's secrets. Run this from the chat where "
                    "the secret was caught.")

        if sub == "status":
            entries = rt.vault.entries(session)
            mode = rt.cfg.get("rehydrate")
            tools = ", ".join(rt.cfg.get("rehydrate_tools") or []) or "none"
            head = (f"Seedguard is on. Rehydration: {mode} (tools: {tools}). "
                    f"Requests redacted: {rt.stats['requests_redacted']}, "
                    f"chat messages cleaned: {rt.stats['gateway_redactions']}, "
                    f"tool calls blocked: {rt.stats['tool_blocks']}, "
                    f"stubbed: {rt.stats['stubbed']}, warnings: {rt.vault.warnings}.")
            if not entries:
                return head + "\nNo secrets caught in this session."
            lines = [head, "", "Protected secrets:"]
            for e in sorted(entries, key=lambda e: e.first_seen):
                state = "ARMED" if e.armed() else "locked"
                if e.armed():
                    state += f" ({int((e.armed_until - time.time()) // 60) + 1} min left)"
                lines.append(f"- [[sg:{e.secret_id}]]  {e.kind}  {e.detail}  seen {e.hits}x, first {_fmt_age(e.first_seen)}  {state}")
            return "\n".join(lines)

        if sub == "arm":
            if not rest:
                return "Usage: /seedguard arm <id|all> [minutes]"
            if rt.cfg.get("rehydrate") == "never":
                return "Rehydration is disabled (rehydrate: never). Nothing to arm."
            minutes = float(rt.cfg.get("arm_minutes_default", 10))
            if len(rest) > 1:
                try:
                    minutes = max(0.5, min(240.0, float(rest[1])))
                except ValueError:
                    return "Minutes must be a number."
            target = rest[0].strip()
            if target.startswith("[[sg:") and target.endswith("]]"):
                target = target[5:-2]
            armed = rt.vault.arm(target, minutes, session)
            if not armed:
                return f"No protected secret matches '{rest[0]}'. Run /seedguard status."
            tools = ", ".join(rt.cfg.get("rehydrate_tools") or [])
            return (f"Armed {', '.join(armed)} for {minutes:g} min. Only these tools can use it: {tools}. "
                    "The model still never sees the value. Run /seedguard disarm to lock early.")

        if sub == "disarm":
            target = rest[0] if rest else "all"
            done = rt.vault.disarm(target, session)
            return f"Locked {', '.join(done)}." if done else "Nothing was armed."

        if sub == "forget":
            target = rest[0] if rest else "all"
            n = rt.vault.forget(target, session)
            rt.redactor.clear_cache()
            return f"Forgot {n} secret(s). Their placeholders will no longer resolve."

        if sub == "log":
            n = 20
            if rest:
                try:
                    n = max(1, min(200, int(rest[0])))
                except ValueError:
                    pass
            events = rt.vault.recent_events(n)
            if not events:
                return "No Seedguard events yet."
            return "\n".join(
                f"{time.strftime('%H:%M:%S', time.localtime(e['ts']))}  {e['action']:<9} {e['kind']:<11} "
                f"{('[[sg:' + e['id'] + ']]') if e.get('id') else '-':<26} {e['where']}"
                for e in events
            )

        if sub == "test":
            text = (raw_args or "").strip()[len(args[0]):].strip()
            if not text:
                return "Usage: /seedguard test <text>"
            new, findings = rt.redactor.redact_text(text, where="test", log=False, session=session)
            if not findings:
                return "Nothing detected."
            lines = [f"- {f.kind} ({f.confidence}, {f.detail}) -> {f.action}" for f in findings]
            return "Detected:\n" + "\n".join(lines) + "\n\nThe model would see:\n" + new

        return f"Unknown subcommand '{sub}'.\n" + HELP

    return handler
