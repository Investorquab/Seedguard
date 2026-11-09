"""Seedguard -- a secret firewall for Hermes Agent.

The model never sees your keys; your tools can still use them.

Seedguard swaps private keys, seed phrases, API keys and one-time codes for
placeholders like ``[[sg:SEED_3fa9c1]]`` before anything reaches the model
provider, and swaps them back only inside the tools you allow, only while you
have armed them. See README.md for the full design and disclosures.
"""

from __future__ import annotations

import logging

__version__ = "0.1.1"

logger = logging.getLogger("seedguard")


def build_runtime(ctx=None, state_dir=None, persist_events=None):
    """Create the vault/redactor/runtime trio. Separate from ``register`` so
    tests and other entry points can build one without a Hermes context."""
    from .config import load_config
    from .hooks import Runtime
    from .redact import Redactor
    from .vault import Vault, default_state_dir

    state = state_dir or default_state_dir()
    cfg = load_config(ctx, state)
    vault = Vault(state, persist_events=cfg["log_events"] if persist_events is None else persist_events)
    rt = Runtime(vault, Redactor(vault, cfg), cfg)
    # Record middleware support from the public ctx surface (no private imports).
    if ctx is not None:
        rt.middleware_supported = hasattr(ctx, "register_middleware")
    return rt


def register(ctx) -> None:
    from .commands import make_handler
    from .hooks import HOOK_NAMES, MIDDLEWARE_KINDS, build_callbacks

    rt = build_runtime(ctx)
    callbacks = build_callbacks(rt)

    if hasattr(ctx, "register_middleware"):
        for kind in MIDDLEWARE_KINDS:
            ctx.register_middleware(kind, callbacks[kind])
    else:  # very old Hermes: hooks-only degraded mode
        logger.warning("seedguard: this Hermes has no middleware API; provider requests are NOT redacted. "
                       "Upgrade Hermes for full protection.")

    for name in HOOK_NAMES:
        ctx.register_hook(name, callbacks[name])

    ctx.register_command(
        "seedguard",
        make_handler(rt),
        description="Secret firewall: status, arm/disarm secrets, event log",
        args_hint="status | arm <id> [min] | disarm | log | test <text>",
    )
    logger.info("seedguard %s loaded (rehydrate=%s)", __version__, rt.cfg["rehydrate"])
