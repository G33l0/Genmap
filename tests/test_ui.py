"""Widget level tests. They run headless through Qt's offscreen platform."""

import shutil

import pytest

from genmap.ui.pages.new_scan.option_tabs import ALL_TABS

ALL_TAB_INDEX = {cls.__name__: i for i, cls in enumerate(ALL_TABS)}

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


def test_profile_keeps_targets(window, context):
    page = window.new_scan
    page.set_targets("192.168.1.10")
    page.option_tabs[ALL_TAB_INDEX["TargetsTab"]].exclusions.setText("192.168.1.1")
    full = next(p for p in context.profiles.list() if p.builtin_key == "full_tcp")
    index = next(i for i in range(page.profile_combo.count()) if page.profile_combo.itemData(i) == full.id)
    page.profile_combo.setCurrentIndex(index)
    page._on_profile_chosen(index)
    assert page.targets.text() == "192.168.1.10"
    assert page._current.ports.mode == PortSelectionMode.ALL
    assert page._current.targets.exclusions == ["192.168.1.1"]
    assert page._profile_id == full.id


def test_save_and_update_profile_from_new_scan(window, context, monkeypatch):
    from genmap.ui.widgets.name_dialog import NameDialog

    page = window.new_scan
    page.set_targets("10.0.0.1")
    page.option_tabs[3].service.setChecked(True)
    page.refresh()
    monkeypatch.setattr(NameDialog, "exec", lambda self: NameDialog.DialogCode.Accepted)
    monkeypatch.setattr(NameDialog, "values", lambda self: ("Web sweep", "Service detection"))
    page.save_as_profile()
    saved = context.profiles.find_by_name("Web sweep")
    assert saved is not None and saved.configuration.service_detection.enabled
    assert saved.configuration.targets.targets == []
    assert page._profile_id == saved.id
    assert not page.update_profile_button.isEnabled()

    page.option_tabs[3].os.setChecked(True)
    page.refresh()
    assert page.update_profile_button.isEnabled()
    from PyQt6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    page.update_profile()
    assert context.profiles.get(saved.id).configuration.os_detection.enabled
    assert not page.update_profile_button.isEnabled()


def test_profiles_page_lists_and_previews(window, context):
    window.show_page("profiles")
    page = window.profiles_page
    names = [page.list.item(i).text() for i in range(page.list.count())]
    assert any(name.startswith("Full TCP") for name in names)
    row = next(i for i, name in enumerate(names) if name.startswith("Full TCP"))
    page.list.setCurrentRow(row)
    assert "-p-" in page.command.toPlainText() and page.command.toPlainText().endswith("<targets>")
    assert page.reset_button.isVisible()
    page._duplicate()
    assert any(page.list.item(i).text() == "Full TCP copy" for i in range(page.list.count()))


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
    from genmap.reporting import result_to_csv

    result = parse_nmap_xml_file(fixtures / "lan_inventory.xml")
    csv_text = result_to_csv(result)
    assert csv_text.splitlines()[0].startswith("host,hostname,host_state,port")
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
    context.scan_index.reconcile(context.run_store)
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


def test_target_group_draft_create_and_scan(window, context):
    window.show_page("targets")
    page = window.targets_page
    page._new()
    assert page._draft and not page.save_button.isEnabled()
    page.name.setText("Lab")
    page.name.textEdited.emit("Lab")
    page.targets_edit.setPlainText("10.0.0.0/30\nfiles.lab.internal")
    page.exclusions_edit.setPlainText("10.0.0.1")
    page._validate()
    assert "2 target expressions" in page.validation.text()
    assert page._save()
    group = next(g for g in context.target_groups.list() if g.name == "Lab")
    assert group.targets == ["10.0.0.0/30", "files.lab.internal"] and group.exclusions == ["10.0.0.1"]
    assert not page._draft and not page.has_unsaved_changes()

    page.targets_edit.setPlainText("10.0.0.300")
    page._validate()
    assert "not a valid" in page.validation.text()
    assert not page.save_button.isEnabled() and not page.scan_button.isEnabled()
    page._show_group()

    page._scan()
    assert window.stack.currentWidget() is window.new_scan
    assert window.new_scan.targets.text() == "10.0.0.0/30, files.lab.internal"
    window.new_scan.refresh()
    assert window.new_scan._current.targets.exclusions == ["10.0.0.1"]


def test_recent_targets_tab(window, context, fixtures):
    from genmap.core.scan_config import ScanConfiguration
    from genmap.engine.run_store import RunStatus

    config = ScanConfiguration()
    config.targets.targets = ["192.168.56.0/29", "scanme.nmap.org"]
    record = context.run_store.create(config)
    shutil.copy(fixtures / "lan_inventory.xml", context.run_store.xml_path(record.run_id))
    record.status = RunStatus.COMPLETED
    context.run_store.save(record)
    context.scan_index.reconcile(context.run_store)
    window.show_page("targets")
    page = window.targets_page
    assert page.recent_table.rowCount() == 2
    page.recent_table.selectAll()
    assert sorted(page._selected_recent()) == ["192.168.56.0/29", "scanme.nmap.org"]
    page.recent_scan.click()
    assert window.stack.currentWidget() is window.new_scan


def test_new_scan_groups_menu(window, context):
    context.target_groups.create("Servers", ["10.1.0.0/24"], ["10.1.0.254"])
    page = window.new_scan
    page._fill_groups_menu()
    actions = [a for a in page.groups_menu.actions() if a.text().startswith("Servers")]
    actions[0].trigger()
    page.refresh()
    assert page._current.targets.targets == ["10.1.0.0/24"]
    assert page._current.targets.exclusions == ["10.1.0.254"]


def _fake_nmap_environment(tmp_path):
    from genmap.nmap.environment import NmapEnvironment
    from genmap.nmap.nse import load_script_catalog

    scripts = tmp_path / "nmapdata" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "script.db").write_text(
        'Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }\n'
        'Entry { filename = "http-brute.nse", categories = { "brute", "intrusive", } }\n'
    )
    (scripts / "http-title.nse").write_text('description = [[\nShows the title of a web page.\n]]\n---\n-- @args http-title.url Path to fetch.\n-- @see http-brute.nse\nauthor = "Test"\ncategories = {"default"}\n')
    (scripts / "http-brute.nse").write_text('description = [[\nGuesses HTTP basic authentication passwords.\n]]\nauthor = "Test"\ncategories = {"brute"}\n')
    env = NmapEnvironment()
    env.data_directory = tmp_path / "nmapdata"
    env.scripts = load_script_catalog(env.data_directory)
    return env


def test_nse_page_browse_filter_and_add(window, context, qtbot, tmp_path):
    env = _fake_nmap_environment(tmp_path)
    context.nmap_module._environment = env
    window.show_page("nse")
    page = window.nse_page
    page._on_environment(env)
    assert page.proxy.rowCount() == 2
    qtbot.waitUntil(lambda: bool(page._docs), timeout=5000)
    page.search.setText("title of a web")
    page._apply_filter()
    assert page.proxy.rowCount() == 1 and page._selected_name() == "http-title"
    assert "http-title.url" in page.details.toPlainText()
    page.search.setText("")
    page.hide_risky.setChecked(True)
    assert page.proxy.rowCount() == 1
    page.hide_risky.setChecked(False)
    page.category.set_current_value("brute")
    assert page.proxy.rowCount() == 1 and page._selected_name() == "http-brute"
    assert "authorized" in page.details.toPlainText()
    page.category.set_current_value("")
    page.select_script("http-title")
    page._add()
    assert "http-title" in window.new_scan.option_tabs[ALL_TAB_INDEX["ScriptsTab"]].expressions.text()
    assert window.new_scan.add_script("http-title") is False
    from PyQt6.QtCore import QUrl

    page._on_link(QUrl("script:http-brute"))
    assert page._selected_name() == "http-brute"


def test_nse_page_without_nmap(window, context):
    from genmap.nmap.environment import NmapEnvironment

    window.show_page("nse")
    window.nse_page._on_environment(NmapEnvironment())
    assert window.nse_page.proxy.rowCount() == 0
    assert "not found" in window.nse_page.count.text()
    assert not window.nse_page.add_button.isEnabled()


def test_reports_page_creates_and_lists(window, context, fixtures, tmp_path, qtbot, monkeypatch):
    from genmap.core.scan_config import ScanConfiguration
    from genmap.engine.run_store import RunStatus

    config = ScanConfiguration()
    config.targets.targets = ["192.168.56.0/29"]
    record = context.run_store.create(config)
    shutil.copy(fixtures / "lan_inventory.xml", context.run_store.xml_path(record.run_id))
    record.status = RunStatus.COMPLETED
    context.run_store.save(record)
    context.scan_index.reconcile(context.run_store)
    window.open_reports_for(record.run_id)
    page = window.reports_page
    assert page.scan.current_value() == record.run_id
    page.folder.setText(str(tmp_path / "out"))
    page._format_buttons["html"].setChecked(True)
    page.create_report()
    qtbot.waitUntil(lambda: page.table.rowCount() == 1, timeout=10000)
    report = context.reports.list()[0]
    assert report.exists and report.path.parent == tmp_path / "out" and report.format == "html"
    page.table.selectRow(0)
    assert page.open_button.isEnabled()
    page._format_buttons["xml"].setChecked(True)
    assert not page.opt_scripts.isEnabled() and not page.title.isEnabled()
    from PyQt6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    page._remove(delete_file=True)
    assert context.reports.list() == [] and not report.path.exists()


def test_settings_storage_rebuild_and_check(window, context, fixtures, qtbot, monkeypatch):
    from genmap.core.scan_config import ScanConfiguration
    from genmap.engine.run_store import RunStatus

    config = ScanConfiguration()
    config.targets.targets = ["192.168.56.0/29"]
    record = context.run_store.create(config)
    shutil.copy(fixtures / "lan_inventory.xml", context.run_store.xml_path(record.run_id))
    record.status = RunStatus.COMPLETED
    context.run_store.save(record)
    window.show_page("settings")
    page = window.settings_page
    page.show_section("Storage")
    page._rebuild_index()
    qtbot.waitUntil(lambda: page.rebuild_button.isEnabled(), timeout=10000)
    assert context.scan_index.get(record.run_id).results_indexed
    assert "1 scans indexed" in page.index_status.text()
    assert "schema 0001" in page.storage_grid._rows["Database"].text()
    from PyQt6.QtWidgets import QMessageBox

    shown = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    page._check_database()
    assert shown and "passed" in shown[0]


def test_flow_layout_wraps_instead_of_squeezing(qtbot):
    from PyQt6.QtWidgets import QPushButton, QWidget

    from genmap.ui.widgets.responsive import FlowLayout

    host = QWidget()
    qtbot.addWidget(host)
    layout = FlowLayout(host)
    buttons = [QPushButton(f"A fairly long button label {i}") for i in range(6)]
    for button in buttons:
        layout.addWidget(button)
    host.resize(1400, 200)
    host.show()
    qtbot.waitUntil(lambda: buttons[-1].y() == buttons[0].y())
    host.resize(420, 400)
    qtbot.waitUntil(lambda: buttons[-1].y() > buttons[0].y())
    assert all(b.width() >= b.sizeHint().width() for b in buttons)
    assert layout.heightForWidth(420) > layout.heightForWidth(1400)
