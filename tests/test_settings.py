import json

import pytest
from pydantic import ValidationError

from genmap.settings import AppSettings, SettingsStore


def test_defaults_when_missing(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    settings = store.load()
    assert settings == AppSettings()
    assert store.load_problem is None


def test_save_and_reload(tmp_path):
    path = tmp_path / "config" / "settings.json"
    store = SettingsStore(path)
    store.load()
    store.settings.appearance.theme = "dark"
    store.settings.nmap.executable_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    store.save()
    again = SettingsStore(path)
    assert again.load().appearance.theme == "dark"
    assert again.settings.nmap.executable_path.endswith("nmap.exe")
    assert not list(path.parent.glob(".settings-*"))


def test_corrupt_file_is_backed_up(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{ this is not json")
    store = SettingsStore(path)
    settings = store.load()
    assert settings == AppSettings()
    assert store.load_problem is not None
    assert list(tmp_path.glob("settings.corrupt-*.json"))


def test_unknown_keys_are_ignored_and_partial_files_work(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"appearance": {"theme": "light", "future": 1}, "retired_section": {}}))
    settings = SettingsStore(path).load()
    assert settings.appearance.theme == "light"
    assert settings.scanning.stats_interval == "2s"


def test_invalid_values_are_rejected():
    settings = AppSettings()
    with pytest.raises(ValidationError):
        settings.scanning.stats_interval = "often"
    with pytest.raises(ValidationError):
        settings.appearance.theme = "neon"


def test_listeners_are_notified(tmp_path):
    store = SettingsStore(tmp_path / "s.json")
    seen = []
    store.subscribe(lambda s: seen.append(s.appearance.theme))
    store.load()
    store.save()
    assert seen == ["system"]
