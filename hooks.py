"""Hermes middleware and hook callbacks.

Layer map (what protects what)
------------------------------
1. ``pre_gateway_dispatch`` (hook)      chat message from Telegram/Discord/...
   is redacted *before* the agent sees it, so the raw secret never reaches
   the session database either.
2. ``llm_request`` (middleware)         every provider request is redacted.
   Observability plugins (``pre_api_request``) then see the redacted view.
3. ``llm_execution`` (middleware)       enforcement: re-checks the exact
   request about to be sent. Hermes middleware is fail-open (an exception
   falls through to the raw request), so this callback never raises before
   ``next_call``: on any internal error it sends a content-free stub instead.
4. ``tool_request`` (middleware)        placeholders in tool args become real
   values only for allowed tools and armed secrets.
5. ``pre_tool_call`` (hook)             blocks tool calls that still carry a
   locked placeholder and tells the model how the user can release it.
6. ``transform_terminal_output`` / ``transform_tool_result`` (hooks)
   tool output (``cat .env``) is redacted before it enters context.
7. ``transform_llm_output`` (hook)      last check on the final reply.

Every callback accepts ``**kwargs`` (Hermes passes extra telemetry fields)
and swallows its own errors -- except layer 3, which fails closed.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from .redact import Redactor, placeholders_in, stub_request
from .vault import Vault, placeholder

logger = logging.getLogger("seedguard")

SOURCE = "seedguard"


class Runtime:
    def __init__(self, vault: Vault, redactor: Redactor, cfg: Dict[str, Any]) -> None:
        self.vault = vault
        self.redactor = redactor
        self.cfg = cfg
        # Set from the public ctx in build_runtime: True/False when this Hermes
        # exposes the middleware API, None when built outside Hermes (tests).
        self.middleware_supported: Optional[bool] = None
        self.stats = {"requests_redacted": 0, "stubbed": 0, "tool_blocks": 0,
                      "rehydrated": 0, "gateway_redactions": 0, "outputs_redacted": 0}


def _summary(findings) -> str:
    kinds: Dict[str, int] = {}
    for f in findings:
        if f.action == "redact":
            kinds[f.kind] = kinds.get(f.kind, 0) + 1
    return ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items()))


def build_callbacks(rt: Runtime) -> Dict[str, Callable[..., Any]]:

    # 2. llm_request ---------------------------------------------------------
    def on_llm_request(request: Any = None, **_: Any) -> Optional[dict]:
        try:
            if not isinstance(request, dict):
                return None
            new, findings = rt.redactor.redact_obj(request, where="llm_request")
            if not any(f.action == "redact" for f in findings):
                return None
            rt.stats["requests_redacted"] += 1
            return {"request": new, "source": SOURCE, "reason": f"redacted {_summary(findings)}"}
        except Exception as exc:  # layer 3 still enforces
            logger.warning("seedguard llm_request failed: %s", exc)
            return None

    # 3. llm_execution (fail-closed) ----------------------------------------
    def on_llm_execution(request: Any = None, next_call: Any = None, **_: Any) -> Any:
        try:
            safe, findings = rt.redactor.redact_obj(request, where="llm_execution")
            if any(f.action == "redact" for f in findings):
                # Layer 2 missed something (or failed). Count it: it is a bug signal.
                rt.stats["requests_redacted"] += 1
                logger.warning("seedguard: secrets reached llm_execution (%s); redacted", _summary(findings))
        except Exception as exc:
            logger.error("seedguard redaction failed, sending stub request: %s", exc)
            rt.stats["stubbed"] += 1
            try:
                safe = stub_request(request)
            except Exception:
                safe = {"messages": [{"role": "user", "content": "[Seedguard blocked this request.]"}]}
        return next_call(safe)

    # 4. tool_request (rehydrate) -------------------------------------------
    def on_tool_request(tool_name: str = "", args: Any = None, **_: Any) -> Optional[dict]:
        try:
            if not isinstance(args, dict) or not placeholders_in(args):
                return None
            new, used, _locked = rt.redactor.rehydrate_obj(args, tool_name)
            if not used:
                return None
            rt.stats["rehydrated"] += len(used)
            for sid in used:
                entry = rt.vault.get(sid)
                rt.vault.log(f"tool:{tool_name}", entry.kind if entry else "?", sid, "rehydrate")
            return {"args": new, "source": SOURCE, "reason": f"released {len(used)} secret(s) to {tool_name}"}
        except Exception as exc:
            logger.warning("seedguard tool_request failed: %s", exc)
            return None

    # 5. pre_tool_call (block locked placeholders) --------------------------
    def on_pre_tool_call(tool_name: str = "", args: Any = None, **_: Any) -> Optional[dict]:
        try:
            ids = placeholders_in(args) if args else []
            if not ids:
                return None
            allowed = rt.cfg.get("rehydrate_tools") or []
            if tool_name not in allowed:
                # Other tools just receive the literal placeholder text (e.g. a
                # memory note or a reply that mentions it). Harmless: no secret
                # leaves the vault.
                return None
            # An executing tool still carrying a placeholder was not released
            # by layer 4. Running it would fail confusingly, so stop and explain.
            rt.stats["tool_blocks"] += 1
            lines = []
            for sid in sorted(set(ids)):
                entry = rt.vault.get(sid)
                if entry is None:
                    why = "is unknown in this session (the user must paste it again)"
                elif tool_name not in allowed:
                    why = f"can never be sent to the '{tool_name}' tool (allowed: {', '.join(allowed) or 'none'})"
                elif rt.cfg.get("rehydrate") == "never":
                    why = "is locked (rehydration is disabled)"
                else:
                    why = f"is locked. Ask the user to run: /seedguard arm {sid}"
                lines.append(f"- {placeholder(sid)} {why}")
                rt.vault.log(f"tool:{tool_name}", entry.kind if entry else "?", sid, "blocked")
            return {
                "action": "block",
                "message": "Seedguard blocked this tool call because it uses a protected secret:\n"
                + "\n".join(lines)
                + "\nDo not try to obtain the secret another way. Tell the user what you need it for.",
            }
        except Exception as exc:
            logger.warning("seedguard pre_tool_call failed: %s", exc)
            return None

    # 6. tool output ---------------------------------------------------------
    def on_transform_terminal_output(output: Any = None, **_: Any) -> Optional[str]:
        try:
            if not isinstance(output, str):
                return None
            new, findings = rt.redactor.redact_text(output, where="terminal_output")
            return new if new != output else None
        except Exception as exc:
            logger.warning("seedguard transform_terminal_output failed: %s", exc)
            return None

    def on_transform_tool_result(result: Any = None, tool_name: str = "", **_: Any) -> Optional[str]:
        try:
            if not isinstance(result, str):
                return None
            new, findings = rt.redactor.redact_text(result, where=f"tool_result:{tool_name}")
            return new if new != result else None
        except Exception as exc:
            logger.warning("seedguard transform_tool_result failed: %s", exc)
            return None

    # 7. final reply ---------------------------------------------------------
    def on_transform_llm_output(response_text: Any = None, **_: Any) -> Optional[str]:
        try:
            if not isinstance(response_text, str):
                return None
            new, findings = rt.redactor.redact_text(response_text, where="llm_output")
            if new != response_text:
                rt.stats["outputs_redacted"] += 1
                return new
            return None
        except Exception as exc:
            logger.warning("seedguard transform_llm_output failed: %s", exc)
            return None

    # 1. inbound chat messages ----------------------------------------------
    def on_pre_gateway_dispatch(event: Any = None, **_: Any) -> Optional[dict]:
        try:
            if not rt.cfg.get("gateway_inbound", True):
                return None
            text = getattr(event, "text", None)
            if not isinstance(text, str) or not text:
                return None
            new, findings = rt.redactor.redact_text(text, where="gateway_inbound")
            if new == text:
                return None
            rt.stats["gateway_redactions"] += 1
            if rt.cfg.get("notify_agent", True):
                new += (
                    "\n\n[Seedguard: this message contained "
                    + _summary(findings)
                    + ". The secret was replaced with a placeholder before you saw it. "
                    "Tell the user to delete their original message from this chat, "
                    "and to treat the secret as exposed to the chat platform.]"
                )
            return {"action": "rewrite", "text": new}
        except Exception as exc:
            logger.warning("seedguard pre_gateway_dispatch failed: %s", exc)
            return None

    return {
        "llm_request": on_llm_request,
        "llm_execution": on_llm_execution,
        "tool_request": on_tool_request,
        "pre_tool_call": on_pre_tool_call,
        "transform_terminal_output": on_transform_terminal_output,
        "transform_tool_result": on_transform_tool_result,
        "transform_llm_output": on_transform_llm_output,
        "pre_gateway_dispatch": on_pre_gateway_dispatch,
    }


MIDDLEWARE_KINDS = ("llm_request", "llm_execution", "tool_request")
HOOK_NAMES = ("pre_tool_call", "transform_terminal_output", "transform_tool_result",
              "transform_llm_output", "pre_gateway_dispatch")
