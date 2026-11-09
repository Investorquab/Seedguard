"""In-memory secret vault and event log.

* Secrets live **only in process memory**. Nothing secret is ever written to
  disk by Seedguard.
* Placeholder ids are ``HMAC-SHA256(install_key, kind|value)[:6]``. The key is
  random per install and stored at ``$HERMES_HOME/seedguard/hmac.key``
  (mode 0600). Stable ids mean the same secret gets the same placeholder on
  every turn and after restarts, so prompt caching keeps working and old
  placeholders in session history still resolve once the secret is seen again.
* The event log (``events.jsonl``) records *kind, id, where, when* -- never the
  value.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as _secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional

# Secrets are stored per conversation. In the CLI there is one session, so this
# default bucket is used; on a multi-user gateway each chat gets its own session
# id (passed by Hermes), so one chat can never see or release another's secrets.
DEFAULT_SESSION = "local"

# Bound how many distinct secrets a single session may hold. Text from a sender
# who has not been admitted yet is still scanned, so this caps what an
# unauthenticated flood can pin in memory; the oldest entry is evicted past it.
MAX_ENTRIES_PER_SESSION = 256


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))


def placeholder(secret_id: str) -> str:
    return f"[[sg:{secret_id}]]"


@dataclass
class SecretEntry:
    secret_id: str
    kind: str
    value: str
    detail: str = ""
    first_seen: float = field(default_factory=time.time)
    hits: int = 0
    armed_until: float = 0.0

    def armed(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) < self.armed_until

    def public(self) -> dict:
        """Everything except the value."""
        return {
            "id": self.secret_id,
            "placeholder": placeholder(self.secret_id),
            "kind": self.kind,
            "detail": self.detail,
            "first_seen": self.first_seen,
            "hits": self.hits,
            "armed": self.armed(),
            "armed_until": self.armed_until if self.armed() else None,
        }


class Vault:
    def __init__(self, state_dir: Optional[Path] = None, persist_events: bool = True,
                 key: Optional[bytes] = None,
                 max_entries_per_session: int = MAX_ENTRIES_PER_SESSION) -> None:
        self.state_dir = Path(state_dir) if state_dir else hermes_home() / "seedguard"
        self.persist_events = persist_events
        self._lock = threading.RLock()
        # session id -> {secret_id -> SecretEntry}. Keyed by conversation so a
        # placeholder caught in one chat only resolves back in that same chat.
        self._sessions: Dict[str, Dict[str, SecretEntry]] = {}
        self._max_entries = max_entries_per_session
        self._events: Deque[dict] = deque(maxlen=500)
        self.warnings = 0
        self._key = key if key is not None else self._load_key()

    # -- key -----------------------------------------------------------------

    def _load_key(self) -> bytes:
        path = self.state_dir / "hmac.key"
        try:
            if path.exists():
                data = path.read_bytes()
                if len(data) >= 32:
                    return data[:32]
            self.state_dir.mkdir(parents=True, exist_ok=True)
            key = _secrets.token_bytes(32)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
            return key
        except OSError:
            # Read-only home: fall back to a per-process key (ids won't be
            # stable across restarts, everything else still works).
            return _secrets.token_bytes(32)

    # -- secrets -------------------------------------------------------------

    def secret_id(self, kind: str, value: str) -> str:
        mac = hmac.new(self._key, f"{kind}|{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{kind}_{mac[:6]}"

    def register(self, kind: str, value: str, detail: str = "",
                 session: str = DEFAULT_SESSION) -> str:
        sid = self.secret_id(kind, value)
        with self._lock:
            bucket = self._sessions.setdefault(session or DEFAULT_SESSION, {})
            entry = bucket.get(sid)
            if entry is None:
                # Keep memory bounded: drop the oldest secret past the cap.
                if len(bucket) >= self._max_entries:
                    oldest = min(bucket, key=lambda k: bucket[k].first_seen)
                    del bucket[oldest]
                entry = SecretEntry(sid, kind, value, detail)
                bucket[sid] = entry
            entry.hits += 1
        return sid

    def get(self, secret_id: str, session: str = DEFAULT_SESSION) -> Optional[SecretEntry]:
        with self._lock:
            return self._sessions.get(session or DEFAULT_SESSION, {}).get(secret_id)

    def entries(self, session: str = DEFAULT_SESSION) -> List[SecretEntry]:
        with self._lock:
            return list(self._sessions.get(session or DEFAULT_SESSION, {}).values())

    def arm(self, target: str, minutes: float, session: str = DEFAULT_SESSION) -> List[str]:
        """Arm one id (or 'all') in a session. Returns the ids that were armed."""
        until = time.time() + minutes * 60
        armed = []
        with self._lock:
            for sid, entry in self._sessions.get(session or DEFAULT_SESSION, {}).items():
                if target in ("all", sid, placeholder(sid)):
                    entry.armed_until = until
                    armed.append(sid)
        return armed

    def disarm(self, target: str = "all", session: str = DEFAULT_SESSION) -> List[str]:
        out = []
        with self._lock:
            for sid, entry in self._sessions.get(session or DEFAULT_SESSION, {}).items():
                if target in ("all", sid, placeholder(sid)) and entry.armed_until:
                    entry.armed_until = 0.0
                    out.append(sid)
        return out

    def forget(self, target: str = "all", session: str = DEFAULT_SESSION) -> int:
        with self._lock:
            bucket = self._sessions.get(session or DEFAULT_SESSION, {})
            ids = [sid for sid in bucket if target in ("all", sid, placeholder(sid))]
            for sid in ids:
                del bucket[sid]
        return len(ids)

    # -- events --------------------------------------------------------------

    def log(self, where: str, kind: str, secret_id: Optional[str], action: str, detail: str = "") -> None:
        event = {"ts": round(time.time(), 3), "where": where, "kind": kind,
                 "id": secret_id, "action": action, "detail": detail}
        with self._lock:
            self._events.append(event)
            if action == "warn":
                self.warnings += 1
        if not self.persist_events:
            return
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            with open(self.state_dir / "events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")
        except OSError:
            pass

    def recent_events(self, n: int = 20) -> List[dict]:
        with self._lock:
            return list(self._events)[-n:]
