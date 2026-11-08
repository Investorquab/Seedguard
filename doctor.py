"""``/seedguard doctor`` -- report the paths Seedguard cannot cover.

Found by the end-to-end test against Hermes 0.19 (see PLAN.md, "Known gaps"):
Hermes' *auxiliary* side-model calls (session titles, context compression,
smart approvals, ...) do not pass through ``llm_request``/``llm_execution``
middleware. A secret typed into the **CLI** is stored raw in the session, so
those side calls can still see it. Secrets sent through a **messaging
gateway** are cleaned by ``pre_gateway_dispatch`` before storage and are safe.

Doctor reads Hermes config read-only and prints concrete fixes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

OK, WARN, INFO = "ok", "warn", "info"


def _load_hermes_config() -> Tuple[Dict[str, Any], str]:
    for loader in ("load_config_readonly", "load_config"):
        try:
            mod = __import__("hermes_cli.config", fromlist=[loader])
            return (getattr(mod, loader)() or {}), ""
        except Exception as exc:  # noqa: PERF203
            err = str(exc)
    return {}, err


def _get(d: Dict[str, Any], *path: str, default: Any = None) -> Any:
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p, default if p == path[-1] else {})
    return d


def _truthy(v: Any, default: bool) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def run_checks(rt: Any, cfg: Dict[str, Any] = None) -> List[Tuple[str, str, str]]:
    checks: List[Tuple[str, str, str]] = []
    if cfg is None:
        cfg, err = _load_hermes_config()
        if err and not cfg:
            checks.append((INFO, "config", f"Could not read Hermes config ({err}); skipping config checks."))

    try:
        import hermes_cli.middleware  # noqa: F401

        checks.append((OK, "middleware", "Provider requests are redacted (llm_request + llm_execution)."))
    except Exception:
        checks.append((WARN, "middleware", "This Hermes has no middleware API: provider requests are NOT redacted. Upgrade Hermes."))

    if _truthy(_get(cfg, "auxiliary", "title_generation", "enabled"), True):
        checks.append((WARN, "titles",
                       "Session titles are written by a side model from your first message. Secrets typed in the CLI "
                       "can reach it (chat-app messages are cleaned first). Fix: set "
                       "auxiliary.title_generation.enabled: false"))
    else:
        checks.append((OK, "titles", "Automatic titles are off."))

    if _truthy(_get(cfg, "compression", "enabled"), True):
        checks.append((WARN, "compression",
                       "Context compression summarises history with a side model. Secrets typed in the CLI can reach "
                       "it. Fix: paste secrets via a chat app, or point auxiliary.compression at a local model."))

    mode = str(_get(cfg, "approvals", "mode", default="smart") or "smart").lower()
    if rt is not None and rt.cfg.get("rehydrate") != "never" and mode == "smart":
        checks.append((WARN, "approvals",
                       "approvals.mode is 'smart': when you arm a secret, the command that uses it is judged by a side "
                       "model and shown in approval prompts. Fix: approvals.mode: manual while using armed secrets."))
    elif mode == "manual":
        checks.append((INFO, "approvals", "Manual approvals: armed secrets appear in your own approval prompt."))

    if rt is not None:
        allowed = rt.cfg.get("rehydrate_tools") or []
        checks.append((INFO, "rehydration", f"mode={rt.cfg.get('rehydrate')}, tools={', '.join(allowed) or 'none'}"))
    return checks


def format_report(checks: List[Tuple[str, str, str]]) -> str:
    icon = {OK: "OK  ", WARN: "WARN", INFO: "info"}
    lines = ["Seedguard doctor:"]
    for level, name, msg in checks:
        lines.append(f"[{icon[level]}] {name}: {msg}")
    warns = sum(1 for c in checks if c[0] == WARN)
    lines.append(f"\n{warns} warning(s)." if warns else "\nAll clear.")
    return "\n".join(lines)
