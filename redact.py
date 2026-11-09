"""Redaction and rehydration engine.

``Redactor.redact_text`` swaps secrets for placeholders like
``[[sg:SEED_3fa9c1]]``; ``Redactor.rehydrate_obj`` swaps placeholders back to
real values inside tool arguments, but only for allowed tools and (by
default) only while the user has armed that secret.
"""

from __future__ import annotations

import copy
import json
import threading
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import enabled_detectors
from .detectors import PLACEHOLDER_RE, REDACT, WARN, Finding, detect_all
from .vault import DEFAULT_SESSION, Vault, placeholder

# Keys in a provider request whose values must never be rewritten: transport
# settings, auth headers, tool schemas, ids.
SKIP_KEYS = frozenset({
    "model", "tools", "tool_choice", "id", "tool_call_id", "type", "role", "name",
    "response_format", "stream", "stream_options", "temperature", "top_p", "max_tokens",
    "max_output_tokens", "max_completion_tokens", "extra_headers", "headers", "extra_body",
    "api_key", "base_url", "timeout", "reasoning", "reasoning_effort", "parallel_tool_calls",
    "store", "seed_value", "n", "stop", "logprobs", "top_logprobs", "service_tier", "prompt_cache_key",
})
MAX_SCAN_CHARS = 2_000_000

STUB_TEXT = (
    "[Seedguard withheld this request because its secret check failed. "
    "Reply exactly: \"Seedguard blocked this request to protect your secrets. "
    "Run /seedguard status and check the Hermes log.\"]"
)


class Redactor:
    def __init__(self, vault: Vault, cfg: Dict[str, Any]) -> None:
        self.vault = vault
        self.cfg = cfg
        self._enabled = enabled_detectors(cfg)
        self._cache: "OrderedDict[Tuple[str, str], Tuple[str, Tuple[Finding, ...]]]" = OrderedDict()
        self._cache_lock = threading.Lock()
        self._cache_max = 4096

    # -- text ----------------------------------------------------------------

    def redact_text(self, text: str, where: str = "unknown", log: bool = True,
                    session: str = DEFAULT_SESSION) -> Tuple[str, List[Finding]]:
        if not isinstance(text, str) or not text or len(text) > MAX_SCAN_CHARS:
            return text, []
        # The cache is keyed by (session, text): the same secret must land in the
        # caller's own session bucket, so a cache hit from another session can't
        # skip that registration.
        cache_key = (session or DEFAULT_SESSION, text)
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._cache.move_to_end(cache_key)
        if cached is not None:
            new_text, findings = cached
            return new_text, list(findings)

        findings = detect_all(text, self._enabled)
        if not findings:
            self._remember(cache_key, text, ())
            return text, []

        parts: List[str] = []
        cursor = 0
        for f in findings:
            if f.action != REDACT:
                if log:
                    self.vault.log(where, f.kind, None, WARN, f.detail)
                continue
            sid = self.vault.register(f.kind, f.value, f.detail, session)
            parts.append(text[cursor:f.start])
            parts.append(placeholder(sid))
            cursor = f.end
            if log:
                self.vault.log(where, f.kind, sid, REDACT, f.detail)
        parts.append(text[cursor:])
        new_text = "".join(parts)
        self._remember(cache_key, new_text, tuple(findings))
        return new_text, findings

    def _remember(self, key: Tuple[str, str], value: str, findings: Tuple[Finding, ...]) -> None:
        with self._cache_lock:
            self._cache[key] = (value, findings)
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    # -- nested objects (provider requests, tool args) -----------------------

    def redact_obj(self, obj: Any, where: str = "unknown", skip_keys: Iterable[str] = SKIP_KEYS,
                   session: str = DEFAULT_SESSION) -> Tuple[Any, List[Finding]]:
        skip = frozenset(skip_keys)
        found: List[Finding] = []

        def walk(node: Any, key: Optional[str] = None) -> Any:
            if key in skip:
                return node
            if isinstance(node, str):
                if node.startswith("data:") and len(node) > 256:
                    return node  # inline image / file payload
                new, fs = self.redact_text(node, where, session=session)
                found.extend(fs)
                return new
            if isinstance(node, dict):
                return {k: walk(v, k) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v) for v in node]
            if isinstance(node, tuple):
                return tuple(walk(v) for v in node)
            return node

        return walk(obj), found

    def contains_secret(self, obj: Any, skip_keys: Iterable[str] = SKIP_KEYS) -> bool:
        """True if any *redactable* secret is still present (no side effects)."""
        skip = frozenset(skip_keys)

        def walk(node: Any, key: Optional[str] = None) -> bool:
            if key in skip:
                return False
            if isinstance(node, str):
                if node.startswith("data:") and len(node) > 256:
                    return False
                return any(f.action == REDACT for f in detect_all(node, self._enabled))
            if isinstance(node, dict):
                return any(walk(v, k) for k, v in node.items())
            if isinstance(node, (list, tuple)):
                return any(walk(v) for v in node)
            return False

        return walk(obj)

    # -- rehydration ---------------------------------------------------------

    def rehydrate_obj(self, obj: Any, tool_name: str,
                      session: str = DEFAULT_SESSION) -> Tuple[Any, List[str], List[str]]:
        """Replace placeholders with real values where policy allows.

        Returns ``(new_obj, used_ids, locked_ids)``. ``locked_ids`` are
        placeholders that were present but not released (unknown *in this
        session*, unarmed, or tool not allowed). Callers block the tool call
        when it is non-empty. Only secrets caught in ``session`` can resolve, so
        a placeholder that leaks into another chat never releases its value.
        """
        mode = self.cfg.get("rehydrate", "armed")
        allowed_tools = set(self.cfg.get("rehydrate_tools") or [])
        used: List[str] = []
        locked: List[str] = []

        def sub(match: Any) -> str:
            sid = f"{match.group(1)}_{match.group(2)}"
            entry = self.vault.get(sid, session)
            ok = (
                entry is not None
                and mode != "never"
                and tool_name in allowed_tools
                and (mode == "always" or entry.armed())
            )
            if ok:
                used.append(sid)
                return entry.value
            locked.append(sid)
            return match.group(0)

        def walk(node: Any) -> Any:
            if isinstance(node, str):
                return PLACEHOLDER_RE.sub(sub, node) if "[[sg:" in node else node
            if isinstance(node, dict):
                return {k: walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v) for v in node]
            return node

        new = walk(obj)
        return new, used, locked


def placeholders_in(obj: Any) -> List[str]:
    try:
        blob = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    except Exception:
        blob = str(obj)
    return [f"{m.group(1)}_{m.group(2)}" for m in PLACEHOLDER_RE.finditer(blob)]


def stub_request(request: Any) -> Dict[str, Any]:
    """A provider request that carries no user content at all.

    Used when redaction itself fails: better a useless reply than a leaked
    secret. Handles OpenAI chat (``messages``), OpenAI Responses (``input`` /
    ``instructions``) and Anthropic (``system`` + ``messages``) shapes.
    """
    base: Dict[str, Any] = {}
    if isinstance(request, dict):
        for k in SKIP_KEYS:
            if k in request and k not in ("tools", "tool_choice", "parallel_tool_calls"):
                base[k] = request[k]
    msg = {"role": "user", "content": STUB_TEXT}
    if isinstance(request, dict) and "input" in request and "messages" not in request:
        base["input"] = [msg]
        if "instructions" in request:
            base["instructions"] = "You are a safety stub."
    else:
        base["messages"] = [msg]
        if isinstance(request, dict) and "system" in request:
            base["system"] = "You are a safety stub."
    return copy.deepcopy(base)
