import pytest

from genmap.core.intrusiveness import assess_intrusiveness, is_high_risk
from genmap.core.nse import ScriptCatalog, ScriptEntry, ScriptExpressionError, select_scripts
from genmap.core.scan_config import ScanConfiguration

CATALOG = ScriptCatalog([
    ScriptEntry("http-title", ("default", "discovery", "safe")),
    ScriptEntry("http-brute", ("brute", "intrusive")),
    ScriptEntry("http-slowloris", ("dos", "vuln")),
    ScriptEntry("ssl-cert", ("default", "discovery", "safe")),
    ScriptEntry("ssl-enum-ciphers", ("discovery", "intrusive")),
    ScriptEntry("smb-vuln-ms17-010", ("safe", "vuln")),
    ScriptEntry("dns-brute", ("brute", "discovery")),
])


def names(expressions):
    return [s.name for s in select_scripts(expressions, CATALOG).scripts]


def test_categories_names_and_wildcards():
    assert names(["default"]) == ["http-title", "ssl-cert"]
    assert names(["http-title"]) == ["http-title"]
    assert names(["http-*"]) == ["http-brute", "http-slowloris", "http-title"]
    assert names(["http-title.nse"]) == ["http-title"]
    assert len(names(["all"])) == len(CATALOG.scripts)


def test_boolean_expressions_follow_nmap_precedence():
    assert names(["not intrusive"]) == ["dns-brute", "http-slowloris", "http-title", "smb-vuln-ms17-010", "ssl-cert"]
    assert names(["default and not ssl-*"]) == ["http-title"]
    assert names(["vuln or brute and intrusive"]) == ["http-brute", "http-slowloris", "smb-vuln-ms17-010"]
    assert names(["(vuln or brute) and intrusive"]) == ["http-brute"]
    assert names(["NOT (safe OR brute)"]) == ["http-slowloris", "ssl-enum-ciphers"]


def test_multiple_expressions_are_a_union():
    assert names(["default", "dns-brute"]) == ["dns-brute", "http-title", "ssl-cert"]


def test_unresolved_terms_and_paths():
    selection = select_scripts(["./custom.nse", "C:\\scripts\\mine.nse", "no-such-script"], CATALOG)
    assert selection.scripts == []
    assert selection.unresolved == ["./custom.nse", "C:\\scripts\\mine.nse", "no-such-script"]


@pytest.mark.parametrize("expression", ["default and", "(default", "and safe", "default or or safe", "default )"])
def test_malformed_expressions(expression):
    with pytest.raises(ScriptExpressionError):
        select_scripts([expression], CATALOG)


def config_with(*scripts, aggressive=False):
    config = ScanConfiguration()
    config.targets.targets = ["10.0.0.1"]
    config.scripts.scripts = list(scripts)
    config.aggressive = aggressive
    return config


def test_safe_selection_has_no_notice():
    assert assess_intrusiveness(config_with("default"), catalog=CATALOG) == []
    assert assess_intrusiveness(config_with("ssl-cert", "smb-vuln-*"), catalog=CATALOG) == []


def test_wildcard_is_reported_only_when_it_really_selects_intrusive_scripts():
    notices = assess_intrusiveness(config_with("ssl-*"), catalog=CATALOG)
    assert is_high_risk(notices)
    assert "1 of the 2 selected scripts" in notices[0].message
    assert "ssl-enum-ciphers" in notices[0].message and "ssl-cert" not in notices[0].message


def test_negation_is_resolved_exactly():
    notices = assess_intrusiveness(config_with("not intrusive"), catalog=CATALOG)
    assert is_high_risk(notices)
    assert "dns-brute" in notices[0].message and "http-slowloris" in notices[0].message
    assert "http-brute" not in notices[0].message


def test_aggressive_mode_includes_default_scripts():
    assert assess_intrusiveness(config_with(aggressive=True), catalog=CATALOG)[0].level == "medium"


def test_unknown_scripts_are_flagged_as_unverifiable():
    notices = assess_intrusiveness(config_with("./custom.nse"), catalog=CATALOG)
    assert [n.level for n in notices] == ["medium"]
    assert "cannot check" in notices[0].message


def test_malformed_expression_is_reported_not_raised():
    notices = assess_intrusiveness(config_with("default and"), catalog=CATALOG)
    assert "could not be checked" in notices[0].message


def test_custom_intrusive_categories():
    assert not is_high_risk(assess_intrusiveness(config_with("smb-vuln-*"), catalog=CATALOG))
    assert is_high_risk(assess_intrusiveness(config_with("smb-vuln-*"), ["vuln"], catalog=CATALOG))
