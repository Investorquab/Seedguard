"""Seedguard configuration.

Precedence (lowest -> highest):
1. ``DEFAULTS`` below
2. ``plugins.entries.seedguard`` in Hermes config, via ``ctx.get_config`` when
   the running Hermes exposes it (newer releases)
3. ``$HERMES_HOME/seedguard/config.yaml`` (optional)
4. Environment variables ``SEEDGUARD_*``
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULTS: Dict[str, Any] = {
    # never | armed | always -- when may a tool receive the real secret?
    "rehydrate": "armed",
    # Only these tools may ever receive a real secret.
    "rehydrate_tools": ["terminal", "execute_code"],
    "arm_minutes_default": 10,
    # Detector switches (see detectors.DETECTORS)
    "detect": {
        "seed": True, "hex_keys": True, "wif": True, "xprv": True, "solana": True,
        "pem": True, "sui": True, "keystore": True, "api_keys": True, "env": True, "otp": True,
    },
    # Redact secrets in chat messages before they reach the agent (gateway).
    "gateway_inbound": True,
    # Tell the agent a secret was caught so it can warn the user.
    "notify_agent": True,
    # Write events.jsonl (kind/id/where only, never values).
    "log_events": True,
}


def _deep_merge(base: Dict[str, Any], extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(extra, dict):
        return base
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_config(ctx: Any = None, state_dir: Optional[Path] = None) -> Dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)

    if ctx is not None and hasattr(ctx, "get_config"):
        try:
            _deep_merge(cfg, ctx.get_config() or {})
        except Exception:
            pass

    if state_dir is not None:
        path = Path(state_dir) / "config.yaml"
        if path.exists():
            try:
                import yaml  # type: ignore

                _deep_merge(cfg, yaml.safe_load(path.read_text(encoding="utf-8")) or {})
            except Exception:
                pass

    env = os.environ
    if env.get("SEEDGUARD_REHYDRATE"):
        cfg["rehydrate"] = env["SEEDGUARD_REHYDRATE"].strip().lower()
    if env.get("SEEDGUARD_REHYDRATE_TOOLS"):
        cfg["rehydrate_tools"] = [t.strip() for t in env["SEEDGUARD_REHYDRATE_TOOLS"].split(",") if t.strip()]
    if env.get("SEEDGUARD_ARM_MINUTES"):
        try:
            cfg["arm_minutes_default"] = float(env["SEEDGUARD_ARM_MINUTES"])
        except ValueError:
            pass
    if env.get("SEEDGUARD_OTP"):
        cfg["detect"]["otp"] = _truthy(env["SEEDGUARD_OTP"])
    if env.get("SEEDGUARD_GATEWAY_INBOUND"):
        cfg["gateway_inbound"] = _truthy(env["SEEDGUARD_GATEWAY_INBOUND"])

    if cfg["rehydrate"] not in ("never", "armed", "always"):
        cfg["rehydrate"] = "armed"
    return cfg


def enabled_detectors(cfg: Dict[str, Any]):
    return [name for name, on in cfg.get("detect", {}).items() if on]
