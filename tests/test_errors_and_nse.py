from genmap.errors import ConfigurationError, GenmapError, NmapNotFoundError, describe_exception
from genmap.nmap.nse import INTRUSIVE_CATEGORIES, load_script_catalog, parse_script_db

SCRIPT_DB = '''
Entry { filename = "acarsd-info.nse", categories = { "discovery", "safe", } }
Entry { filename = "afp-brute.nse", categories = { "brute", "intrusive", } }
Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }
'''


def test_error_carries_message_remedy_and_cause():
    try:
        try:
            raise OSError("permission denied")
        except OSError as inner:
            raise GenmapError("Could not save.", remedy="Check permissions.", details="path=/x", cause=inner)
    except GenmapError as exc:
        message, remedy, details = describe_exception(exc)
    assert message == "Could not save."
    assert remedy == "Check permissions."
    assert "path=/x" in details and "permission denied" in details


def test_default_messages():
    assert str(NmapNotFoundError()) == "Nmap executable was not found."
    assert isinstance(ConfigurationError(), ValueError)


def test_describe_plain_exception():
    message, remedy, details = describe_exception(ValueError("bad"))
    assert message == "ValueError: bad" and remedy is None and "ValueError" in details


def test_parse_script_db():
    entries = parse_script_db(SCRIPT_DB)
    assert [e.name for e in entries] == ["acarsd-info", "afp-brute", "http-title"]
    brute = entries[1]
    assert brute.is_intrusive and brute.categories == ("brute", "intrusive")
    assert not entries[2].is_intrusive
    assert "exploit" in INTRUSIVE_CATEGORIES


def test_catalog_from_directory(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "script.db").write_text(SCRIPT_DB)
    catalog = load_script_catalog(tmp_path)
    assert catalog.categories == ["brute", "default", "discovery", "intrusive", "safe"]
    assert [s.name for s in catalog.by_category("default")] == ["http-title"]
    assert load_script_catalog(tmp_path / "missing").scripts == []
    assert load_script_catalog(None).scripts == []
