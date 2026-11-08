"""Integration test against a real Hermes install.

Loads Seedguard through Hermes' own PluginManager from a temporary
HERMES_HOME, then drives the *real* middleware/hook call helpers that the
agent loop uses. Skipped automatically when hermes-agent isn't installed
(``pip install hermes-agent``).
"""

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytest.importorskip("hermes_cli.middleware")

ROOT = Path(__file__).resolve().parents[1]

SCRIPT = textwrap.dedent(r'''
    import json, sys
    from types import SimpleNamespace
    from hermes_cli import plugins as P
    from hermes_cli.middleware import (apply_llm_request_middleware, run_llm_execution_middleware,
                                       apply_tool_request_middleware)

    P.discover_plugins(force=True)
    mgr = P.get_plugin_manager()
    loaded = mgr._plugins.get("seedguard")
    assert loaded is not None, f"not discovered: {list(mgr._plugins)}"
    assert loaded.enabled and not loaded.error, loaded.error

    SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    req = {"model": "m", "messages": [{"role": "user", "content": f"seed {SEED} private key {KEY}"}]}

    r = apply_llm_request_middleware(req, session_id="s")
    assert r.changed and SEED not in json.dumps(r.payload) and KEY not in json.dumps(r.payload)

    sent = {}
    run_llm_execution_middleware(req, lambda q: sent.setdefault("q", q), original_request=req)
    assert SEED not in json.dumps(sent["q"])

    # placeholder for the key, as the model would see it
    import re
    ph = re.findall(r"\[\[sg:EVM_KEY_[0-9a-f]{6}\]\]", json.dumps(r.payload))[0]
    sid = ph[5:-2]
    args = {"command": f"cast wallet address --private-key {ph}"}

    t = apply_tool_request_middleware("terminal", args)
    assert not t.changed  # locked by default
    block = P.get_pre_tool_call_block_message("terminal", args) if hasattr(P, "get_pre_tool_call_block_message") else None
    assert block and "seedguard arm" in block.lower(), block

    handler = P.get_plugin_command_handler("seedguard")
    assert "Armed" in handler(f"arm {sid} 2")
    t = apply_tool_request_middleware("terminal", args)
    assert t.changed and t.payload["command"].endswith(KEY)

    out = P.invoke_hook("transform_terminal_output", command="cat .env", output="DB_PASSWORD=hunter2hunter2", returncode=0)
    assert out and "hunter2hunter2" not in out[0]

    gw = P.invoke_hook("pre_gateway_dispatch", event=SimpleNamespace(text=f"words {SEED}"), gateway=None, session_store=None)
    assert gw and gw[0]["action"] == "rewrite" and SEED not in gw[0]["text"]

    status = handler("status")
    assert SEED not in status and KEY not in status and "EVM_KEY_" in status
    print("INTEGRATION_OK")
''')


def test_loads_and_runs_inside_real_hermes(tmp_path):
    home = tmp_path / "hermes_home"
    (home / "plugins").mkdir(parents=True)
    shutil.copytree(ROOT, home / "plugins" / "seedguard",
                    ignore=shutil.ignore_patterns("tests", "__pycache__", ".pytest_cache", "*.zip"))
    (home / "config.yaml").write_text("plugins:\n  enabled:\n    - seedguard\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SEEDGUARD_")}
    env["HERMES_HOME"] = str(home)
    proc = subprocess.run([sys.executable, "-c", SCRIPT], env=env, capture_output=True, text=True,
                          timeout=120, cwd=str(tmp_path))
    assert "INTEGRATION_OK" in proc.stdout, proc.stdout[-3000:] + "\n---\n" + proc.stderr[-3000:]
