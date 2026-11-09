"""State lives under Hermes' per-plugin data dir (review recommendation).

Seedguard persists its hmac.key and events.jsonl under
``<hermes home>/plugin-data/seedguard`` via the documented
``plugins.plugin_storage.plugin_data_dir`` helper, and falls back to
``<hermes home>/seedguard`` when that helper isn't available.
"""
import sys
import types

from seedguard import vault as V


def test_fallback_without_hermes_helper(monkeypatch, tmp_path):
    # Ensure the helper is not importable, and pin a known hermes home.
    monkeypatch.setitem(sys.modules, "plugins.plugin_storage", None)
    monkeypatch.setattr(V, "hermes_home", lambda: tmp_path)
    assert V.default_state_dir() == tmp_path / "seedguard"


def test_prefers_plugin_data_dir_when_available(monkeypatch, tmp_path):
    calls = {}

    def fake_plugin_data_dir(name):
        calls["name"] = name
        d = tmp_path / "plugin-data" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    pkg = types.ModuleType("plugins")
    pkg.__path__ = []  # mark as a package so the submodule import resolves
    mod = types.ModuleType("plugins.plugin_storage")
    mod.plugin_data_dir = fake_plugin_data_dir
    monkeypatch.setitem(sys.modules, "plugins", pkg)
    monkeypatch.setitem(sys.modules, "plugins.plugin_storage", mod)

    assert V.default_state_dir() == tmp_path / "plugin-data" / "seedguard"
    assert calls["name"] == "seedguard"


def test_vault_default_uses_default_state_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(V, "default_state_dir", lambda: tmp_path / "chosen")
    v = V.Vault(persist_events=False, key=b"k" * 32)
    assert v.state_dir == tmp_path / "chosen"
