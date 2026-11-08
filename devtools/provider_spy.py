#!/usr/bin/env python3
"""provider_spy -- see exactly what your model provider receives.

An OpenAI-compatible HTTP endpoint that logs every request body Hermes sends
and highlights anything that looks like a secret (using Seedguard's own
detectors) or a Seedguard placeholder. Two modes:

* mock (default): answers with canned replies, no network, no API key.
  ``--script toolcall`` makes the first reply a ``terminal`` tool call that
  uses the first Seedguard placeholder it sees -- handy to demo arming.
* proxy: ``--upstream https://openrouter.ai/api/v1`` forwards to a real
  provider (your Authorization header is passed through, never logged) and
  still logs the bodies. Use this for the demo video.

Point Hermes at it (``~/.hermes/config.yaml``)::

    model:
      provider: custom
      base_url: http://127.0.0.1:8787/v1
      default: <model name>     # anything in mock mode

Stdlib only. Run: ``python devtools/provider_spy.py --port 8787``
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))  # parent of the plugin dir -> `import seedguard`

try:
    from seedguard.detectors import REDACT, detect_all  # type: ignore
except Exception:  # spy still works without the detectors
    detect_all = None
    REDACT = "redact"

PLACEHOLDER = re.compile(r"\[\[sg:[A-Z0-9_]+_[0-9a-f]{6}\]\]")
RED, GREEN, DIM, BOLD, RESET = "\033[31m", "\033[32m", "\033[2m", "\033[1m", "\033[0m"

STATE = {"n": 0, "lock": threading.Lock()}


def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            if k not in ("tools",):
                yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


def analyse(body: dict):
    leaks, placeholders = [], set()
    for s in strings(body):
        placeholders.update(PLACEHOLDER.findall(s))
        if detect_all:
            for f in detect_all(s):
                if f.action == REDACT:
                    leaks.append((f.kind, f.value))
    return leaks, sorted(placeholders)


def last_user_text(body: dict) -> str:
    for m in reversed(body.get("messages") or []):
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, list):
                return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
            return c or ""
    return ""


def log_request(body: dict, args) -> None:
    with STATE["lock"]:
        STATE["n"] += 1
        n = STATE["n"]
    leaks, phs = analyse(body)
    if args.log:
        with open(args.log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"n": n, "ts": time.time(), "leaks": [k for k, _ in leaks],
                                 "placeholders": phs, "body": body}) + "\n")
    user = last_user_text(body)
    print(f"\n{BOLD}── request #{n} → model {body.get('model')!r} ─────────────────{RESET}")
    print(f"{DIM}last user message the MODEL sees:{RESET}\n  {user[:600]}")
    if phs:
        print(f"{GREEN}✔ Seedguard placeholders: {', '.join(phs)}{RESET}")
    if leaks:
        for kind, value in leaks:
            print(f"{RED}✘ RAW SECRET REACHED THE PROVIDER: {kind}: {value[:12]}…{RESET}")
    elif detect_all:
        print(f"{GREEN}✔ no raw secrets in this request{RESET}")
    sys.stdout.flush()


def mock_reply(body: dict, args) -> dict:
    msgs = body.get("messages") or []
    saw_tool_result = any(m.get("role") == "tool" for m in msgs[-3:])
    if args.script == "toolcall" and not saw_tool_result:
        _, phs = analyse(body)
        cmd = f"echo key-length: $(printf %s '{phs[0]}' | wc -c)" if phs else "echo no placeholder seen"
        return {"role": "assistant", "content": None, "tool_calls": [{
            "id": f"call_{STATE['n']}", "type": "function",
            "function": {"name": "terminal", "arguments": json.dumps({"command": cmd})}}]}
    _, phs = analyse(body)
    text = "I can see these protected placeholders: " + ", ".join(phs) if phs else "Hello from the provider spy."
    return {"role": "assistant", "content": text}


class Handler(BaseHTTPRequestHandler):
    server_version = "provider-spy/0.1"
    args = None

    def log_message(self, *a):  # quiet default access log
        pass

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            return self._json(200, {"object": "list", "data": [{"id": "spy-model", "object": "model"}]})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        log_request(body, self.args)
        if self.args.upstream:
            return self._forward(raw)
        msg = mock_reply(body, self.args)
        finish = "tool_calls" if msg.get("tool_calls") else "stop"
        if body.get("stream"):
            return self._stream(body, msg, finish)
        self._json(200, {
            "id": f"chatcmpl-spy{STATE['n']}", "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model", "spy-model"),
            "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        })

    def _stream(self, body, msg, finish):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        base = {"id": f"chatcmpl-spy{STATE['n']}", "object": "chat.completion.chunk",
                "created": int(time.time()), "model": body.get("model", "spy-model")}
        delta = {"role": "assistant"}
        if msg.get("content"):
            delta["content"] = msg["content"]
        if msg.get("tool_calls"):
            delta["tool_calls"] = [dict(tc, index=i) for i, tc in enumerate(msg["tool_calls"])]
        for chunk in (
            dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": None}]),
            dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": finish}],
                 usage={"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}),
        ):
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _forward(self, raw: bytes):
        url = self.args.upstream.rstrip("/") + self.path.replace("/v1", "", 1)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() in ("authorization", "content-type", "accept", "http-referer", "x-title")}
        if self.args.upstream_key_env:
            import os
            key = os.environ.get(self.args.upstream_key_env, "")
            if key:
                headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
                headers["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(url, data=raw, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=600) as up:
                self.send_response(up.status)
                for k, v in up.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(k, v)
                self.end_headers()
                while True:
                    chunk = up.read(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except urllib.error.HTTPError as e:
            self._json(e.code, {"error": e.read().decode(errors="replace")[:2000]})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--upstream", default="", help="real OpenAI-compatible base URL to forward to")
    ap.add_argument("--upstream-key-env", default="",
                    help="name of an env var holding the real provider key (e.g. OPENROUTER_API_KEY); "
                         "replaces whatever key Hermes sent, so Hermes can use a dummy key")
    ap.add_argument("--script", choices=["echo", "toolcall"], default="echo", help="mock behaviour")
    ap.add_argument("--log", default="", help="append request bodies as JSONL to this file")
    args = ap.parse_args()
    Handler.args = args
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    mode = f"proxy → {args.upstream}" if args.upstream else f"mock ({args.script})"
    print(f"provider_spy listening on http://127.0.0.1:{args.port}/v1  [{mode}]")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
