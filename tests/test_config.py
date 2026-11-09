"""Hermes plugin settings actually apply (review blocker #1).

``ctx.get_config`` has the signature ``get_config(key, default=None)``. Calling
it with no key raised a TypeError that was swallowed, so no plugin setting ever
took effect. Settings are now read one key at a time.
"""
from seedguard.config import load_config


class FakeCtx:
    """Mimics Hermes: get_config(key, default) over a settings dict."""

    def __init__(self, settings):
        self._settings = settings
        self.calls = []

    def get_config(self, key, default=None):
        self.calls.append(key)
        return self._settings.get(key, default)


class NoKeyCtx:
    """A ctx whose get_config *requires* a key -- the old no-arg call broke here."""

    def get_config(self, key, default=None):
        if key is None:
            raise TypeError("key is required")
        return default


def test_settings_are_read_by_key(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("SEEDGUARD_"):
            monkeypatch.delenv(k, raising=False)
    ctx = FakeCtx({"rehydrate": "never", "rehydrate_tools": ["execute_code"],
                   "arm_minutes_default": 25, "gateway_inbound": False})
    cfg = load_config(ctx)
    assert cfg["rehydrate"] == "never"
    assert cfg["rehydrate_tools"] == ["execute_code"]
    assert cfg["arm_minutes_default"] == 25
    assert cfg["gateway_inbound"] is False
    # It read each setting by name (never a keyless call).
    assert "rehydrate" in ctx.calls and None not in ctx.calls


def test_detect_subsettings_merge(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("SEEDGUARD_"):
            monkeypatch.delenv(k, raising=False)
    ctx = FakeCtx({"detect": {"otp": False}})
    cfg = load_config(ctx)
    assert cfg["detect"]["otp"] is False      # overridden
    assert cfg["detect"]["seed"] is True       # defaults preserved


def test_keyful_ctx_does_not_break(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("SEEDGUARD_"):
            monkeypatch.delenv(k, raising=False)
    cfg = load_config(NoKeyCtx())
    assert cfg["rehydrate"] == "armed"          # falls back to defaults cleanly


def test_env_still_overrides_ctx(monkeypatch):
    monkeypatch.setenv("SEEDGUARD_REHYDRATE", "always")
    ctx = FakeCtx({"rehydrate": "never"})
    cfg = load_config(ctx)
    assert cfg["rehydrate"] == "always"         # env wins over plugin settings
