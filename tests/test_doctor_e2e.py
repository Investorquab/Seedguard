import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from seedguard.commands import make_handler
from seedguard.doctor import WARN, run_checks

ROOT = Path(__file__).resolve().parents[1]


def test_doctor_defaults_warn_about_aux_paths(rt):
    checks = {name: level for level, name, _ in run_checks(rt, cfg={})}
    assert checks["titles"] == WARN and checks["compression"] == WARN and checks["approvals"] == WARN


def test_doctor_hardened_config(rt):
    cfg = {"auxiliary": {"title_generation": {"enabled": False}}, "compression": {"enabled": False},
           "approvals": {"mode": "manual"}}
    # The "middleware" check warns only when this Hermes has no middleware API
    # (e.g. hermes-agent not installed in the test env); it is environment-, not
    # config-driven, so a hardened *config* leaves no other warning behind.
    warns = [n for lvl, n, _ in run_checks(rt, cfg=cfg) if lvl == WARN and n != "middleware"]
    assert warns == []


def test_doctor_command_runs(rt):
    assert "Seedguard doctor" in make_handler(rt)("doctor")


@pytest.mark.skipif(not os.environ.get("SEEDGUARD_E2E"), reason="set SEEDGUARD_E2E=1 to run real `hermes chat` e2e")
def test_e2e_real_hermes():
    hermes = shutil.which("hermes")
    assert hermes, "hermes binary not on PATH"
    proc = subprocess.run([sys.executable, str(ROOT / "devtools" / "e2e_check.py"), "--hermes", hermes],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout + proc.stderr
