#!/usr/bin/env python3
"""End-to-end check: real `hermes chat -q` -> Seedguard -> provider_spy.

Starts provider_spy in mock mode, builds a throwaway HERMES_HOME with
Seedguard installed, runs Hermes one-shot, and reports every request the
"provider" received, flagging raw secrets.

Scenarios
---------
default    titles ON  -> expect main request clean; the auxiliary title call
           leaks (known gap, see PLAN.md). Exit 0 if the main loop is clean.
hardened   titles OFF, rehydrate=always, spy scripted to emit a terminal tool
           call with the placeholder -> expect zero leaks and the tool to run
           with the real value.

Usage: python devtools/e2e_check.py [--hermes /path/to/hermes] [--scenario default|hardened|all]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil test key #0


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run(hermes: str, scenario: str) -> bool:
    tmp = Path(tempfile.mkdtemp(prefix=f"sg-e2e-{scenario}-"))
    home = tmp / "home"
    (home / "plugins").mkdir(parents=True)
    shutil.copytree(PLUGIN, home / "plugins" / "seedguard",
                    ignore=shutil.ignore_patterns("tests", "__pycache__", ".pytest_cache", "*.zip"))
    port = free_port()
    hardened = scenario == "hardened"
    cfg = [
        "model:", "  provider: custom", f"  base_url: http://127.0.0.1:{port}/v1", "  default: spy-model",
        "plugins:", "  enabled:", "    - seedguard",
        "approvals:", "  mode: \"off\"" if hardened else "  mode: smart",
    ]
    if hardened:
        cfg += ["auxiliary:", "  title_generation:", "    enabled: false"]
    (home / "config.yaml").write_text("\n".join(cfg) + "\n")
    (home / ".env").write_text("OPENAI_API_KEY=sk-dummy-local-spy\n")

    log = tmp / "spy.jsonl"
    spy_args = [sys.executable, str(PLUGIN / "devtools" / "provider_spy.py"), "--port", str(port), "--log", str(log)]
    if hardened:
        spy_args += ["--script", "toolcall"]
    spy = subprocess.Popen(spy_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(1.0)

    env = {k: v for k, v in os.environ.items() if not k.startswith("SEEDGUARD_")}
    env["HERMES_HOME"] = str(home)
    if hardened:
        env["SEEDGUARD_REHYDRATE"] = "always"
    prompt = (f"my wallet seed is {SEED} and my private key {KEY}. "
              "please check the key length with the terminal")
    try:
        proc = subprocess.run([hermes, "chat", "-q", prompt], env=env, cwd=str(tmp),
                              capture_output=True, text=True, timeout=180)
    finally:
        spy.terminate()
        spy.wait(timeout=5)

    requests = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    print(f"\n=== scenario: {scenario}  (HERMES_HOME={home}) ===")
    main_clean, any_leak = True, False
    for r in requests:
        msgs = r["body"].get("messages") or []
        first = str(msgs[0].get("content", ""))[:60] if msgs else ""
        is_aux = "title" in first.lower()
        tag = "aux:title" if is_aux else "main"
        status = "LEAK " + ",".join(r["leaks"]) if r["leaks"] else "clean"
        print(f"  #{r['n']:<2} {tag:<10} {status:<14} placeholders={r['placeholders']}")
        if r["leaks"]:
            any_leak = True
            if not is_aux:
                main_clean = False
    tool_ran = "key-length" in proc.stdout or "key-length" in json.dumps(requests)
    if hardened:
        print(f"  terminal tool received real key (value never shown to model): {tool_ran}")
    if proc.returncode != 0:
        print("  hermes exit code", proc.returncode, proc.stderr[-1500:])
    ok = main_clean and (not hardened or (not any_leak and tool_ran))
    print("  RESULT:", "PASS" if ok else "FAIL")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hermes", default=shutil.which("hermes") or "hermes")
    ap.add_argument("--scenario", default="all", choices=["default", "hardened", "all"])
    a = ap.parse_args()
    scenarios = ["default", "hardened"] if a.scenario == "all" else [a.scenario]
    results = [run(a.hermes, s) for s in scenarios]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
