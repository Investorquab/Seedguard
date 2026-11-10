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
from .vault import DEFAULT_SESSION, Vault, placeholder

logger = logging.getLogger("seedguard")

SOURCE = "seedguard"


# A gateway chat whose identity could not be computed. Used as an *isolated*
# vault bucket on the defensive redaction path (the model is still protected) and
# as a refusal signal for the slash command. It is deliberately NOT the shared CLI
# default ``DEFAULT_SESSION`` -- that is the bug this fixes: one chat's catches must
# never surface in, or be wiped by, another chat.
NO_SESSION = "\x00seedguard-no-session"

# Non-chat client surfaces. The CLI / TUI / desktop are a single local session with
# no cross-chat concern, so they share the one default bucket. (``Platform.LOCAL`` is
# ``"local"``; the CLI slash-command path reports ``"cli"``.)
_LOCAL_SURFACES = frozenset({"", "cli", "local", "tui", "desktop"})

_SESSION_ENV: Any = None
_SESSION_ENV_TRIED = False


def _session_env():
    """Hermes' public per-session context reader (``gateway.session_context``),
    or ``None`` when running outside a gateway process (CLI tools, unit tests)."""
    global _SESSION_ENV, _SESSION_ENV_TRIED
    if not _SESSION_ENV_TRIED:
        _SESSION_ENV_TRIED = True
        try:
            from gateway.session_context import get_session_env  # public API
            _SESSION_ENV = get_session_env
        except Exception:
            _SESSION_ENV = None
    return _SESSION_ENV


def _compose(platform: Any, chat_id: Any, thread_id: Any, user_id: Any) -> str:
    """Build the canonical vault key from the four identity fields every path shares.

    The key must be byte-identical whether it is computed on the inbound path from
    ``event.source`` or read back on the turn/tool paths from
    ``get_session_env("HERMES_SESSION_*")``. The gateway binds those env vars from
    the very same ``SessionSource`` as ``str(x) if x else ""`` (see
    ``gateway/run.py`` ``_set_session_env``), so this normalises identically.
    """
    platform = str(platform) if platform else ""
    chat_id = str(chat_id) if chat_id else ""
    thread_id = str(thread_id) if thread_id else ""
    user_id = str(user_id) if user_id else ""
    if not chat_id:
        # No chat id: a local client is the single default session; a real messaging
        # surface we cannot key is isolated (never the shared default).
        return DEFAULT_SESSION if platform.lower() in _LOCAL_SURFACES else NO_SESSION
    return "\x1f".join(("sg1", platform, chat_id, thread_id, user_id))


def _from_source(src: Any) -> str:
    """Key a ``SessionSource`` (``event.source`` on inbound, the ``source`` kwarg on a
    gateway command). ``platform`` is a ``Platform`` enum -> ``.value``.

    The turn/tool paths read the key back from ``HERMES_SESSION_*``, which the gateway
    binds through ``gateway.session_detached.session_env_source``. That helper drops the
    user from a *shared, non-DM* chat's route (Telegram observe mode etc.), binding
    ``HERMES_SESSION_USER_ID`` empty. We mirror that strip here so the inbound/command
    key matches the turn-path key for the same chat -- otherwise a secret pasted in a
    group could be armed but never released to a tool. (A DM's chat id already
    identifies the user, so nothing is lost.)
    """
    platform = getattr(getattr(src, "platform", None), "value", None)
    if platform is None:
        platform = getattr(src, "platform", None)  # already a plain string
    user_id = getattr(src, "user_id", None)
    if getattr(src, "shared_session", False) and getattr(src, "chat_type", None) != "dm":
        user_id = None
    return _compose(platform, getattr(src, "chat_id", None),
                    getattr(src, "thread_id", None), user_id)


def _offgateway(kwargs: Dict[str, Any]) -> str:
    """CLI / programmatic callers: an explicit session id, else the one local session."""
    for key in ("session_id", "session", "chat_id", "conversation_id"):
        v = kwargs.get(key)
        if isinstance(v, (str, int)):
            s = str(v).strip()
            if s:
                return s
    return DEFAULT_SESSION


def session_of(kwargs: Dict[str, Any], *, event: Any = None, command: bool = False) -> str:
    """The vault key for this call, keyed by a chat identity every path can compute,
    so a secret caught in one chat is never visible to -- or releasable by -- another.

    Three entry contexts, each knowing its own shape (``MessageEvent`` carries no
    session/chat id of its own -- the id lives on ``event.source``):

    * **Gateway inbound** (``event=`` given): runs before the session is bound, so the
      identity comes from ``event.source``.
    * **Slash command** (``command=True``): core passes a ``SessionSource`` as ``source``
      on a gateway, or ``source=None`` + ``platform="cli"`` on the CLI.
    * **Turn / tool middleware and output hooks** (neither): the gateway has bound the
      full identity in task-local context vars; the callback kwargs carry only
      ``platform`` + ``session_id``, so the identity is read from ``get_session_env``.

    Returns ``NO_SESSION`` for a gateway event/command whose chat cannot be identified;
    callers refuse rather than fall back to the shared default bucket. Off a gateway
    (CLI, tests) it falls back to an explicit ``session_id`` or the single default.
    """
    if event is not None:
        src = getattr(event, "source", None)
        return _from_source(src) if src is not None else NO_SESSION
    if command:
        src = kwargs.get("source")
        return _from_source(src) if src is not None else _offgateway(kwargs)
    env = _session_env()
    if env is not None:
        platform = env("HERMES_SESSION_PLATFORM")
        chat_id = env("HERMES_SESSION_CHAT_ID")
        if chat_id or (platform and str(platform).strip().lower() not in _LOCAL_SURFACES):
            return _compose(platform, chat_id,
                            env("HERMES_SESSION_THREAD_ID"), env("HERMES_SESSION_USER_ID"))
    return _offgateway(kwargs)


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
    def on_llm_request(request: Any = None, **kwargs: Any) -> Optional[dict]:
        try:
            if not isinstance(request, dict):
                return None
            new, findings = rt.redactor.redact_obj(request, where="llm_request",
                                                   session=session_of(kwargs))
            if not any(f.action == "redact" for f in findings):
                return None
            rt.stats["requests_redacted"] += 1
            return {"request": new, "source": SOURCE, "reason": f"redacted {_summary(findings)}"}
        except Exception as exc:  # layer 3 still enforces
            logger.warning("seedguard llm_request failed: %s", exc)
            return None

    # 3. llm_execution (fail-closed) ----------------------------------------
    def on_llm_execution(request: Any = None, next_call: Any = None, **kwargs: Any) -> Any:
        try:
            safe, findings = rt.redactor.redact_obj(request, where="llm_execution",
                                                    session=session_of(kwargs))
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
    def on_tool_request(tool_name: str = "", args: Any = None, **kwargs: Any) -> Optional[dict]:
        try:
            if not isinstance(args, dict) or not placeholders_in(args):
                return None
            session = session_of(kwargs)
            new, used, _locked = rt.redactor.rehydrate_obj(args, tool_name, session=session)
            if not used:
                return None
            rt.stats["rehydrated"] += len(used)
            for sid in used:
                entry = rt.vault.get(sid, session)
                rt.vault.log(f"tool:{tool_name}", entry.kind if entry else "?", sid, "rehydrate")
            return {"args": new, "source": SOURCE, "reason": f"released {len(used)} secret(s) to {tool_name}"}
        except Exception as exc:
            logger.warning("seedguard tool_request failed: %s", exc)
            return None

    # 5. pre_tool_call (block locked placeholders) --------------------------
    def on_pre_tool_call(tool_name: str = "", args: Any = None, **kwargs: Any) -> Optional[dict]:
        try:
            ids = placeholders_in(args) if args else []
            if not ids:
                return None
            session = session_of(kwargs)
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
                entry = rt.vault.get(sid, session)
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
    def on_transform_terminal_output(output: Any = None, **kwargs: Any) -> Optional[str]:
        try:
            if not isinstance(output, str):
                return None
            new, findings = rt.redactor.redact_text(output, where="terminal_output",
                                                    session=session_of(kwargs))
            return new if new != output else None
        except Exception as exc:
            logger.warning("seedguard transform_terminal_output failed: %s", exc)
            return None

    def on_transform_tool_result(result: Any = None, tool_name: str = "", **kwargs: Any) -> Optional[str]:
        try:
            if not isinstance(result, str):
                return None
            new, findings = rt.redactor.redact_text(result, where=f"tool_result:{tool_name}",
                                                    session=session_of(kwargs))
            return new if new != result else None
        except Exception as exc:
            logger.warning("seedguard transform_tool_result failed: %s", exc)
            return None

    # 7. final reply ---------------------------------------------------------
    def on_transform_llm_output(response_text: Any = None, **kwargs: Any) -> Optional[str]:
        try:
            if not isinstance(response_text, str):
                return None
            new, findings = rt.redactor.redact_text(response_text, where="llm_output",
                                                    session=session_of(kwargs))
            if new != response_text:
                rt.stats["outputs_redacted"] += 1
                return new
            return None
        except Exception as exc:
            logger.warning("seedguard transform_llm_output failed: %s", exc)
            return None

    # 1. inbound chat messages ----------------------------------------------
    def on_pre_gateway_dispatch(event: Any = None, **kwargs: Any) -> Optional[dict]:
        try:
            if not rt.cfg.get("gateway_inbound", True):
                return None
            text = getattr(event, "text", None)
            if not isinstance(text, str) or not text:
                return None
            new, findings = rt.redactor.redact_text(text, where="gateway_inbound",
                                                    session=session_of(kwargs, event=event))
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
