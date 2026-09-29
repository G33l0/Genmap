"""Headless self test for packaged builds.

``genmap --self-test report.json`` exercises the parts of the application a
broken bundle would fail on (imports, bundled resources, Qt plugins, the XML
parser, command building, every page, every theme) in a throwaway data folder,
then writes a JSON report. A windowed executable has no console, so the report
file and the exit code are the only outputs.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Callable

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80 192.0.2.10" start="1700000000" version="7.95" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>
<host><status state="up" reason="echo-reply" reason_ttl="64"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<ports><extraports state="closed" count="1"><extrareasons reason="reset" count="1" proto="tcp" ports="80"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6</cpe></service></port></ports>
</host>
<runstats><finished time="1700000005" elapsed="5.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

# The same host a day later: port 80 now answers and a traceroute was recorded.
LATER_XML = SAMPLE_XML.replace(
    '<extraports state="closed" count="1"><extrareasons reason="reset" count="1" proto="tcp" ports="80"/></extraports>',
    '<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/>'
    '<service name="http" product="nginx" method="probed" conf="10"/></port>',
).replace(
    "</ports>\n</host>",
    '</ports>\n<trace port="22" proto="tcp"><hop ttl="1" ipaddr="198.51.100.1" rtt="0.50"/>'
    '<hop ttl="3" ipaddr="192.0.2.10" rtt="4.20"/></trace>\n</host>',
).replace('start="1700000000"', 'start="1700086400"')


def run_self_test(report_path: Path) -> int:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    os.environ["GENMAP_HOME"] = tempfile.mkdtemp(prefix="genmap-selftest-")
    checks: list[dict] = []
    started = time.perf_counter()

    def check(name: str, fn: Callable[[], object]) -> object:
        t0 = time.perf_counter()
        try:
            detail = fn()
            checks.append({"name": name, "ok": True, "detail": detail, "seconds": round(time.perf_counter() - t0, 3)})
            return detail
        except BaseException as exc:  # noqa: BLE001 - every failure must land in the report
            checks.append({
                "name": name,
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            })
            return None

    from PyQt6.QtCore import QCoreApplication, QEvent
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv[:1])

    def resources():
        from genmap.resources import ICON_ICO, app_icon, logo_pixmap

        assert ICON_ICO.is_file(), f"missing {ICON_ICO}"
        assert not app_icon().isNull(), "application icon is empty"
        assert not logo_pixmap(64).isNull(), "logo could not be rendered"
        return f"icons in {ICON_ICO.parent}"

    def parser():
        from genmap.nmap.xml_parser import parse_nmap_xml_string

        result = parse_nmap_xml_string(SAMPLE_XML)
        assert result.total_open_ports == 1 and result.identified_services == {"ssh"}
        return result.summary_line()

    def secure_parser():
        from genmap.errors import XmlParseError
        from genmap.nmap.xml_parser import parse_nmap_xml_string

        hostile = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun args="&a;"/>'
        try:
            parse_nmap_xml_string(hostile)
        except XmlParseError:
            return "entity declarations rejected"
        raise AssertionError("entity declaration was accepted")

    def command():
        from genmap.core.presets import PRESETS
        from genmap.nmap.command_builder import build_command_plan

        rendered = []
        for preset in PRESETS:
            config = preset.build()
            config.targets.targets = ["192.0.2.10"]
            plan = build_command_plan(Path("nmap"), config, xml_output=Path("result.xml"))
            assert plan.arguments[-1] == "192.0.2.10"
            rendered.append(plan.display())
        return f"{len(rendered)} presets build valid commands"

    def settings():
        from genmap.paths import default_paths
        from genmap.settings import SettingsStore

        paths = default_paths().ensure()
        store = SettingsStore(paths.settings_file)
        store.load()
        store.settings.appearance.theme = "hacker"
        store.save()
        assert SettingsStore(paths.settings_file).load().appearance.theme == "hacker"
        return str(paths.settings_file)

    def environment():
        from genmap.nmap.environment import probe_environment

        env = probe_environment(timeout=15)
        return {
            "nmap_usable": env.usable,
            "version": str(env.version) if env.version else None,
            "data_files_found": [s.spec.name for s in env.data_files if s.found],
            "diagnostics": [f"{d.level.value}: {d.title}" for d in env.diagnostics],
        }

    def interface():
        from genmap.paths import default_paths
        from genmap.settings import SettingsStore
        from genmap.ui.app_context import AppContext
        from genmap.ui.main_window import MainWindow
        from genmap.ui.theme.palettes import THEME_CHOICES

        paths = default_paths().ensure()
        store = SettingsStore(paths.settings_file)
        store.load()
        context = AppContext(app, paths, store)
        window = MainWindow(context)
        visited = []
        try:
            window._warned_missing = True
            window.show()
            window.start()
            for key in window.pages:
                window.show_page(key)
                app.processEvents()
                visited.append(key)
            for key, _caption in THEME_CHOICES:
                context.theme.apply(key)
                app.processEvents()
            from genmap.nmap.xml_parser import parse_nmap_xml_string

            window.results._display(parse_nmap_xml_string(SAMPLE_XML), None, Path("sample.xml"))
            assert window.results.proxy.rowCount() == 1
            window.new_scan.set_targets("192.0.2.10")
            window.new_scan.refresh()
            assert window.new_scan._current is not None, "New Scan form did not produce a configuration"

            from genmap.core.comparison import ScanSide, compare_scans
            from genmap.topology import TopologySource, build_topology, layered_layout

            exports = paths.data_dir / "selftest-exports"
            before, after = parse_nmap_xml_string(SAMPLE_XML), parse_nmap_xml_string(LATER_XML)
            compare = window.compare_page
            compare._result = compare_scans(ScanSide(before, "before", ["192.0.2.10"]), ScanSide(after, "after", ["192.0.2.10"]))
            compare._pair = ("before", "after")
            compare._show_result()
            assert compare.export_to("html", exports / "compare.html") is not None, "comparison export failed"
            topology = window.topology_page
            topology._graph = build_topology([TopologySource(after, "after")])
            topology._positions = layered_layout(topology._graph)
            topology._draw()
            for fmt in ("svg", "png"):
                written = topology.export_to(fmt, exports / f"map.{fmt}")
                assert written is not None and written.stat().st_size > 0, f"map export as {fmt} failed"
        finally:
            window.settings_page._dirty = False
            window.close()
            context.shutdown()
            window.deleteLater()
            context.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        return f"pages {', '.join(visited)}; themes {', '.join(k for k, _ in THEME_CHOICES)}; comparison and map exports written"

    def database():
        from genmap.core.scan_config import ScanConfiguration
        from genmap.engine.run_store import RunStatus, RunStore
        from genmap.paths import default_paths
        from genmap.storage import open_database
        from genmap.storage.profiles import ProfileRepository
        from genmap.storage.scans import ScanIndex

        paths = default_paths().ensure()
        db = open_database(paths.data_dir / "selftest.sqlite3")
        try:
            revision = db.current_revision()
            assert revision is not None, "migrations did not run"
            seeded = ProfileRepository(db).seed_builtins([])
            assert seeded, "built in profiles were not seeded"
            store = RunStore(paths.data_dir / "selftest-scans")
            config = ScanConfiguration()
            config.targets.targets = ["192.0.2.10"]
            record = store.create(config)
            store.xml_path(record.run_id).write_text(SAMPLE_XML, encoding="utf-8")
            record.status = RunStatus.COMPLETED
            store.save(record)
            report = ScanIndex(db).reconcile(store)
            assert report.indexed == 1, f"index report {report}"
            assert db.integrity_ok()
        finally:
            db.dispose()
        return f"schema {revision}, {len(seeded)} profiles seeded, sample scan indexed"

    def reports():
        from genmap.nmap.xml_parser import parse_nmap_xml_string
        from genmap.paths import default_paths
        from genmap.reporting import ReportSource, generate_report

        folder = default_paths().ensure().data_dir / "selftest-reports"
        source = ReportSource(parse_nmap_xml_string(SAMPLE_XML))
        written = [generate_report(source, fmt, folder / f"report.{fmt}").name for fmt in ("html", "json", "csv")]
        html_text = (folder / "report.html").read_text(encoding="utf-8")
        assert "OpenSSH" in html_text and "default-src 'none'" in html_text
        return ", ".join(written)

    def comparison_and_topology():
        from genmap.core.comparison import ChangeKind, ScanSide, compare_scans
        from genmap.nmap.xml_parser import parse_nmap_xml_string
        from genmap.topology import EdgeKind, NodeKind, TopologySource, build_topology

        before, after = parse_nmap_xml_string(SAMPLE_XML), parse_nmap_xml_string(LATER_XML)
        result = compare_scans(ScanSide(before, "before", ["192.0.2.10"]), ScanSide(after, "after", ["192.0.2.10"]))
        kinds = [c.kind for c in result.changes()]
        assert kinds == [ChangeKind.PORT_OPENED], f"unexpected changes {kinds}"
        graph = build_topology([TopologySource(after, "after")])
        assert graph.count(NodeKind.NO_REPLY) == 1 and graph.count(NodeKind.ROUTER) == 1
        assert {e.kind for e in graph.edges.values()} == {EdgeKind.ROUTE, EdgeKind.GAP}
        return "1 port change found; route with one silent hop drawn"

    check("bundled resources", resources)
    check("xml parser", parser)
    check("xml parser rejects entities", secure_parser)
    check("command builder", command)
    check("settings round trip", settings)
    check("comparison and topology", comparison_and_topology)
    check("nmap environment probe", environment)
    check("database and migrations", database)
    check("reports", reports)
    check("user interface", interface)

    from genmap import __version__

    ok = all(c["ok"] for c in checks)
    report = {
        "genmap_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "ok": ok,
        "seconds": round(time.perf_counter() - started, 2),
        "checks": checks,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if ok else 1
