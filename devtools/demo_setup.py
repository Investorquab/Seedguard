#!/usr/bin/env python3
"""Create an isolated Hermes "demo home" for recording the Seedguard video.

It does NOT touch your normal ~/.hermes. Everything lives in ./demo_home:

* Seedguard installed and enabled
* Hermes pointed at provider_spy (so the right-hand terminal shows exactly
  what the model receives)
* demo-safe settings: auto titles off, approvals manual (see /seedguard doctor)

Usage
-----
    python devtools/demo_setup.py --model <openrouter model id>        # real model via OpenRouter
    python devtools/demo_setup.py --mock                               # no account needed (canned replies)

Then follow the two commands it prints (one per terminal window).
Your real provider key is read by the spy from the OPENROUTER_API_KEY
environment variable at runtime. It is never written into any file.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", default=str(PLUGIN.parent / "demo_home"))
    ap.add_argument("--model", default="", help="OpenRouter model id, e.g. the one you use with Hermes")
    ap.add_argument("--mock", action="store_true", help="use the spy's canned replies, no real model")
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    if not a.mock and not a.model:
        ap.error("pass --model <openrouter model id> or --mock")

    home = Path(a.home).resolve()
    (home / "plugins").mkdir(parents=True, exist_ok=True)
    target = home / "plugins" / "seedguard"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(PLUGIN, target, ignore=shutil.ignore_patterns(
        "tests", "__pycache__", ".pytest_cache", "*.zip", ".git", "demo_home"))

    model = a.model or "spy-model"
    (home / "config.yaml").write_text(
        "model:\n"
        "  provider: custom\n"
        f"  base_url: http://127.0.0.1:{a.port}/v1\n"
        f"  default: {model}\n"
        "plugins:\n  enabled:\n    - seedguard\n"
        "approvals:\n  mode: manual\n"
        "auxiliary:\n  title_generation:\n    enabled: false\n",
        encoding="utf-8",
    )
    # Hermes -> spy uses a dummy key; the spy swaps in the real one.
    (home / ".env").write_text("OPENAI_API_KEY=dummy-key-for-local-spy\n", encoding="utf-8")

    py = sys.executable
    spy = PLUGIN / "devtools" / "provider_spy.py"
    spy_args = f'--port {a.port}' + ('' if a.mock else ' --upstream https://openrouter.ai/api/v1 --upstream-key-env OPENROUTER_API_KEY')

    (home / "run_spy.sh").write_text(f'#!/usr/bin/env bash\n"{py}" "{spy}" {spy_args}\n', encoding="utf-8")
    (home / "run_hermes.sh").write_text(f'#!/usr/bin/env bash\nHERMES_HOME="{home}" hermes "$@"\n', encoding="utf-8")
    (home / "run_spy.ps1").write_text(f'& "{py}" "{spy}" {spy_args}\n', encoding="utf-8")
    (home / "run_hermes.ps1").write_text(f'$env:HERMES_HOME = "{home}"\nhermes @args\n', encoding="utf-8")
    for f in ("run_spy.sh", "run_hermes.sh"):
        (home / f).chmod(0o755)

    print(f"Demo home ready: {home}\n")
    if not a.mock:
        print("Before step 1, put your OpenRouter key in an environment variable in THAT terminal")
        print("(type it yourself, never paste it into a chat):")
        print("  macOS/Linux:  export OPENROUTER_API_KEY=...")
        print("  Windows:      $env:OPENROUTER_API_KEY = \"...\"\n")
    print("Terminal 1 (right side of the screen, the 'what the model sees' view):")
    print(f"  macOS/Linux:  bash \"{home / 'run_spy.sh'}\"")
    print(f"  Windows:      powershell -File \"{home / 'run_spy.ps1'}\"\n")
    print("Terminal 2 (left side, chat with Hermes):")
    print(f"  macOS/Linux:  bash \"{home / 'run_hermes.sh'}\"")
    print(f"  Windows:      powershell -File \"{home / 'run_hermes.ps1'}\"\n")
    print("Inside Hermes, first run:  /seedguard doctor   then follow DEMO.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
