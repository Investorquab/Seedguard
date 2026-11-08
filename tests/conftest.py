"""Make the plugin importable as ``seedguard`` from its own repo checkout.

The repo root *is* the plugin package (plugin.yaml + __init__.py), so we put
its parent directory on sys.path. The checkout folder must be named
``seedguard`` (it is, in the zip and in the GitHub repo).
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))


@pytest.fixture
def rt(tmp_path, monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("SEEDGUARD_"):
            monkeypatch.delenv(k, raising=False)
    import seedguard

    return seedguard.build_runtime(state_dir=tmp_path, persist_events=False)
