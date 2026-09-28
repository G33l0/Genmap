import json


def test_self_test_passes_and_writes_report(qapp, tmp_path, monkeypatch):
    from genmap.selftest import run_self_test

    monkeypatch.setenv("GENMAP_HOME", str(tmp_path / "home"))
    report_path = tmp_path / "report.json"
    assert run_self_test(report_path) == 0
    report = json.loads(report_path.read_text())
    assert report["ok"] is True
    assert {c["name"] for c in report["checks"]} >= {"bundled resources", "xml parser", "user interface"}
    assert all(c["ok"] for c in report["checks"])


def test_self_test_reports_failures(qapp, tmp_path, monkeypatch):
    from genmap.selftest import run_self_test

    monkeypatch.setenv("GENMAP_HOME", str(tmp_path / "home"))

    def broken(*_args, **_kwargs):
        raise RuntimeError("simulated parser failure")

    monkeypatch.setattr("genmap.nmap.xml_parser.parse_nmap_xml_string", broken)
    report_path = tmp_path / "report.json"
    assert run_self_test(report_path) == 1
    report = json.loads(report_path.read_text())
    failed = [c for c in report["checks"] if not c["ok"]]
    assert report["ok"] is False
    assert any("simulated parser failure" in c["error"] for c in failed)
