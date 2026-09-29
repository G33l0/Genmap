import pytest

from genmap.core.intrusiveness import assess_intrusiveness, is_high_risk
from genmap.core.presets import PRESETS, preset_by_key
from genmap.core.scan_config import ScanConfiguration, TcpScanTechnique, validate_configuration
from genmap.nmap.command_builder import build_user_arguments


@pytest.mark.parametrize("preset", PRESETS, ids=lambda p: p.key)
def test_presets_are_valid_configurations(preset):
    config = preset.build()
    config.targets.targets = ["10.0.0.1"]
    assert not [i for i in validate_configuration(config) if i.severity == "error"]
    build_user_arguments(config)
    assert config.name == preset.name


def test_unknown_preset_falls_back_to_default():
    assert preset_by_key("missing").key == "default"


def base():
    config = ScanConfiguration()
    config.targets.targets = ["10.0.0.1"]
    return config


def test_plain_scan_has_no_notices():
    assert assess_intrusiveness(base()) == []


def test_intrusive_categories_are_flagged():
    config = base()
    config.scripts.scripts = ["default", "vuln and brute"]
    notices = assess_intrusiveness(config)
    assert is_high_risk(notices)
    assert "brute" in notices[0].message


def test_negated_category_is_not_reported_as_selected_without_catalog():
    config = base()
    config.scripts.scripts = ["not intrusive"]
    notices = assess_intrusiveness(config)
    assert not is_high_risk(notices)
    assert any("not" in n.message for n in notices)


def test_wildcards_and_script_names():
    config = base()
    config.scripts.scripts = ["http-*"]
    assert is_high_risk(assess_intrusiveness(config))
    config.scripts.scripts = ["ssh-brute"]
    assert is_high_risk(assess_intrusiveness(config))


def test_scope_and_spoofing():
    config = base()
    config.targets.targets = ["10.0.0.0/16"]
    config.evasion.decoys = ["RND:5"]
    config.techniques.tcp = TcpScanTechnique.SYN
    messages = [n.message for n in assess_intrusiveness(config)]
    assert any("65,536" in m for m in messages)
    assert any("Decoys" in m for m in messages)


def test_random_targets_are_high_risk():
    config = ScanConfiguration()
    config.targets.random_targets = 100
    assert is_high_risk(assess_intrusiveness(config))


def test_custom_category_list():
    config = base()
    config.scripts.scripts = ["discovery"]
    assert assess_intrusiveness(config) == []
    assert is_high_risk(assess_intrusiveness(config, ["discovery"]))
