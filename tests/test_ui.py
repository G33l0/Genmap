"""Widget level tests. They run headless through Qt's offscreen platform."""

import shutil

import pytest

from genmap.core.scan_config import PortSelectionMode
from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.xml_parser import parse_nmap_xml_file
from genmap.settings import SettingsStore


def _flush_deletions(qapp):
    from PyQt6.QtCore import QCoreApplication, QEvent

    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    qapp.processEvents()


@pytest.fixture
def context(qapp, app_paths):
    from genmap.ui.app_context import AppContext

    store = SettingsStore(app_paths.settings_file)
    store.load()
    ctx = AppContext(qapp, app_paths, store)
    yield ctx
    ctx.shutdown()
    ctx.deleteLater()
    _flush_deletions(qapp)


@pytest.fixture
def window(qapp, context):
    from genmap.ui.main_window import MainWindow

    win = MainWindow(context)
    win._warned_missing = True  # keep the startup message box out of headless tests
    win.show()
    win.start()
    yield win
    # Deleting explicitly keeps later tests from restyling windows left over from earlier ones.
    win.settings_page._dirty = False
    win.close()
    win.deleteLater()
    _flush_deletions(qapp)


def test_main_window_pages_and_navigation(window):
    for key in ("dashboard", "new_scan", "scan_monitor", "results", "history", "modules", "settings"):
        window.show_page(key)
        assert window.stack.currentWidget() is window.pages[key]
    assert window.windowTitle().startswith("Genmap | ")
    assert not window.windowIcon().isNull()


def test_missing_nmap_is_reported_without_crashing(window):
    window._on_environment(NmapEnvironment())
    assert window.nmap_status.text() == "Nmap not available"
    window.show_page("new_scan")
    window.new_scan.set_targets("10.0.0.1")
    window.new_scan.refresh()
    assert not window.new_scan.start_button.isEnabled()
    assert "not available" in window.new_scan.start_button.toolTip()


def test_new_scan_form_builds_configuration(window):
    page = window.new_scan
    page.set_targets("10.0.0.0/30, scanme.nmap.org")
    ports_tab = page.option_tabs[1]
    ports_tab.mode_specific.setChecked(True)
    ports_tab.specification.setText("22,80,443")
    page.option_tabs[3].service.setChecked(True)
    page.option_tabs[4].expressions.setText("default, http-title")
    page.option_tabs[9].arguments.setText("--max-retries 1")
    page.refresh()
    config = page._current
    assert config is not None
    assert config.targets.targets == ["10.0.0.0/30", "scanme.nmap.org"]
    assert config.ports.mode == PortSelectionMode.SPECIFIC
    assert config.scripts.scripts == ["default", "http-title"]
    command = page.command_view.toPlainText()
    for piece in ("-p 22,80,443", "-sV", "--script=default,http-title", "--max-retries 1", "10.0.0.0/30 scanme.nmap.org"):
        assert piece in command
    assert "2 targets" in page.target_status.text()


def test_new_scan_reports_invalid_input(window):
    page = window.new_scan
    page.set_targets("10.0.0.300")
    ports_tab = page.option_tabs[1]
    ports_tab.mode_specific.setChecked(True)
    ports_tab.specification.setText("80,,443")
    page.refresh()
    assert page._current is None
    texts = [page.issue_list.item(i).text() for i in range(page.issue_list.count())]
    assert any("targets" in t for t in texts)
    assert any("ports.specification" in t for t in texts)
    assert not page.start_button.isEnabled()


def test_category_checkboxes_sync_with_expression(window):
    tab = window.new_scan.option_tabs[4]
    tab._category_checks["safe"].setChecked(True)
    assert "safe" in tab.expressions.text()
    tab.expressions.setText("vuln")
    assert tab._category_checks["vuln"].isChecked()
    assert not tab._category_checks["safe"].isChecked()


def test_preset_keeps_targets(window):
    page = window.new_scan
    page.set_targets("192.168.1.10")
    index = next(i for i in range(page.preset.count()) if page.preset.itemData(i) == "full_tcp")
    page.preset.setCurrentIndex(index)
    page._on_preset_chosen(index)
    assert page.targets.text() == "192.168.1.10"
    assert page._current.ports.mode == PortSelectionMode.ALL


def test_results_filtering(window, fixtures):
    page = window.results
    xml = fixtures / "lan_inventory.xml"
    page._display(parse_nmap_xml_file(xml), None, xml)
    assert page.proxy.rowCount() == 3  # the down host is hidden by default
    page.hide_down.setChecked(False)
    assert page.proxy.rowCount() == 4

    page.filter_field.set_current_value("service")
    page.filter_text.setText("ssh")
    assert page._filter_timer.isActive()  # typing is debounced
    page._apply_filter()
    assert page.proxy.rowCount() == 1
    host_index = page.proxy.index(0, 0)
    assert page.proxy.rowCount(host_index) == 1

    page.filter_field.set_current_value("os")
    page.filter_text.setText("routeros")
    page._apply_filter()
    assert page.proxy.rowCount() == 1

    page.filter_field.set_current_value("all")
    page.filter_text.setText("")
    page._apply_filter()
    page.filter_state.set_current_value("filtered")
    assert page.proxy.rowCount() == 2
    page.filter_state.set_current_value("")
    assert page.port_model.rowCount() == 11

    page.tree.setCurrentIndex(page.proxy.index(0, 0))
    assert "192.168.56.1" in page.details.toPlainText()


def test_results_export(window, fixtures, tmp_path, monkeypatch):
    from genmap.ui.pages.results.page import result_to_csv

    result = parse_nmap_xml_file(fixtures / "lan_inventory.xml")
    csv_text = result_to_csv(result)
    assert csv_text.splitlines()[0].startswith("host,hostname,port")
    assert len(csv_text.strip().splitlines()) == 12


def test_history_lists_runs(window, context, fixtures):
    from genmap.core.scan_config import ScanConfiguration
    from genmap.engine.run_store import RunStatus

    config = ScanConfiguration()
    config.targets.targets = ["192.168.56.0/29"]
    record = context.run_store.create(config, profile_name="Network inventory")
    shutil.copy(fixtures / "lan_inventory.xml", context.run_store.xml_path(record.run_id))
    record.status = RunStatus.COMPLETED
    context.run_store.save(record)
    window.show_page("history")
    assert window.history.model.rowCount() == 1
    assert window.history.open_button.isEnabled()
    window.show_page("dashboard")
    assert window.dashboard.last_title.text() == "192.168.56.0/29"


def test_settings_save_and_validation(window, context, monkeypatch):
    page = window.settings_page
    window.show_page("settings")
    shown = []
    monkeypatch.setattr("genmap.ui.pages.settings.page.show_error", lambda *a, **k: shown.append(a))
    from genmap.ui.widgets.inputs import EnumCombo

    combo = page._sections[1].widget().findChildren(EnumCombo)[0]
    combo.set_current_value("dark")
    page._mark_dirty()
    assert page.save()
    assert context.settings.appearance.theme == "dark"
    assert context.theme.palette.is_dark

    interval = next(w for w in page._sections[4].widget().findChildren(type(page.nmap_path)) if w.placeholderText() == "e.g. 2s")
    interval.setText("sometimes")
    page._mark_dirty()
    assert not page.save()
    assert shown
    page.revert()
    assert interval.text() == "2s"


def test_responsive_grid_columns(qtbot):
    from PyQt6.QtWidgets import QLabel

    from genmap.ui.widgets.responsive import ResponsiveGrid

    grid = ResponsiveGrid({0: 1, 900: 2})
    qtbot.addWidget(grid)
    for text in ("a", "b", "c"):
        grid.add(QLabel(text))
    assert grid.columns_for(600) == 1
    assert grid.columns_for(1200) == 2
    grid.resize(1200, 400)
    grid.show()
    qtbot.waitUntil(lambda: grid._columns == 2)
    grid.resize(500, 400)
    qtbot.waitUntil(lambda: grid._columns == 1)


def test_logo_resources(qapp):
    from genmap.resources import ICON_ICO, app_icon, logo_pixmap

    assert ICON_ICO.is_file() and ICON_ICO.stat().st_size > 1000
    assert not app_icon().isNull()
    pixmap = logo_pixmap(48, 2.0)
    assert pixmap.width() == 96 and not pixmap.toImage().isNull()


def test_hacker_theme_applies_and_menu_keeps_unsaved_settings(window, context):
    page = window.settings_page
    window.show_page("settings")
    timeout_field = next(w for w in page._sections[4].widget().findChildren(type(page.nmap_path)) if w.placeholderText() == "e.g. 2s")
    timeout_field.setText("5s")
    page._mark_dirty()
    window._theme_actions["hacker"].trigger()
    assert context.settings.appearance.theme == "hacker"
    assert context.theme.palette.name == "hacker"
    assert "monospace" in context.app.styleSheet()
    assert page.has_unsaved_changes() and timeout_field.text() == "5s"
    assert page.theme_combo.current_value() == "hacker"
    context.theme.apply("light")


def test_monitor_attach_keeps_engine_connections(window, context):
    from pathlib import Path

    from genmap.core.scan_config import ScanConfiguration
    from genmap.engine.scan_engine import ScanJob
    from genmap.nmap.command_builder import build_command_plan

    def make_job():
        config = ScanConfiguration()
        config.targets.targets = ["127.0.0.1"]
        record = context.run_store.create(config)
        return ScanJob(record, build_command_plan(Path("nmap"), config), context.run_store)

    first, second = make_job(), make_job()
    seen = []
    first.finished.connect(lambda record: seen.append(record.run_id))
    window.monitor.attach(first)
    window.monitor.attach(second)
    first.finished.emit(first.record)
    assert seen == [first.record.run_id]


def test_monitor_service_caption_reflects_version_detection(window, context):
    from pathlib import Path

    from genmap.core.scan_config import ScanConfiguration
    from genmap.engine.scan_engine import ScanJob
    from genmap.nmap.command_builder import build_command_plan

    config = ScanConfiguration()
    config.targets.targets = ["127.0.0.1"]
    job = ScanJob(context.run_store.create(config), build_command_plan(Path("nmap"), config), context.run_store)
    window.monitor.attach(job)
    assert "port table" in window.monitor.metric_services.caption_label.text()
    config.service_detection.enabled = True
    job = ScanJob(context.run_store.create(config), build_command_plan(Path("nmap"), config), context.run_store)
    window.monitor.attach(job)
    assert window.monitor.metric_services.caption_label.text() == "Services identified"


@pytest.mark.parametrize("theme", ["light", "dark", "hacker"])
def test_theme_writes_indicator_images(qapp, tmp_path, theme):
    from genmap.ui.theme.manager import ThemeManager

    manager = ThemeManager(qapp, asset_dir=tmp_path / "assets")
    manager.apply(theme)
    sheet = qapp.styleSheet()
    images = sorted((tmp_path / "assets").glob(f"*-{theme}-*.svg"))
    assert len(images) == 6
    for image in images:
        assert image.as_posix() in sheet
    assert "QComboBox::down-arrow" in sheet and "QCheckBox::indicator:checked" in sheet
