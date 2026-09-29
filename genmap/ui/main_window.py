"""Main application window: sidebar navigation and page stack."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QByteArray, QSettings, Qt, QUrl
from PyQt6.QtGui import QAction, QActionGroup, QCloseEvent, QDesktopServices, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from genmap import APP_NAME, __version__
from genmap.core.diagnostics import DiagnosticLevel
from genmap.core.scan_config import ScanConfiguration
from genmap.core.targets import split_target_text
from genmap.engine.scan_engine import ScanJob
from genmap.nmap.environment import NmapEnvironment
from genmap.resources import app_icon, logo_pixmap
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.compare import ComparePage
from genmap.ui.pages.dashboard import DashboardPage
from genmap.ui.pages.history import HistoryPage
from genmap.ui.pages.modules import ModulesPage
from genmap.ui.pages.new_scan import NewScanPage
from genmap.ui.pages.nse import NsePage
from genmap.ui.pages.profiles import ProfilesPage
from genmap.ui.pages.reports import ReportsPage
from genmap.ui.pages.targets import TargetsPage
from genmap.ui.pages.results import ResultsPage
from genmap.ui.pages.scan_monitor import ScanMonitorPage
from genmap.ui.pages.settings import SettingsPage
from genmap.ui.pages.topology import TopologyPage
from genmap.ui.theme.palettes import THEME_CHOICES
from genmap.ui.widgets.common import label, set_status
from genmap.ui.widgets.sidebar import NavEntry, Sidebar

log = logging.getLogger(__name__)

PROJECT_URL = "https://github.com/g33l0/genmap"

NAV_ENTRIES = [
    NavEntry("dashboard", "Dashboard", "Overview and quick scan (Ctrl+1)"),
    NavEntry("new_scan", "New Scan", "Configure and start a scan (Ctrl+N)"),
    NavEntry("scan_monitor", "Live Scan", "The scan running now or most recently"),
    NavEntry("results", "Results", "Browse hosts, ports, and script output"),
    NavEntry("history", "Scan History", "Previous scans (Ctrl+H)"),
    NavEntry("compare", "Compare", "Differences between two scans"),
    NavEntry("targets", "Targets", "Saved target groups and recently scanned targets"),
    NavEntry("profiles", "Profiles", "Reusable scan configurations"),
    NavEntry("nse", "NSE Scripts", "Browse the scripts installed with Nmap"),
    NavEntry("topology", "Topology", "Network paths from Nmap traceroute data"),
    NavEntry("reports", "Reports", "HTML, JSON, CSV, and XML reports from stored scans"),
    NavEntry("modules", "Modules", "Registered tool modules"),
    NavEntry("settings", "Settings", "Nmap location, appearance, and behaviour (Ctrl+,)"),
]


class AboutDialog(QDialog):
    def __init__(self, parent: QWidget, env: Optional[NmapEnvironment]) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        top = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(logo_pixmap(72, self.devicePixelRatioF()))
        top.addWidget(logo, 0, Qt.AlignmentFlag.AlignTop)
        titles = QVBoxLayout()
        titles.addWidget(label(APP_NAME, role="title"))
        titles.addWidget(label(f"Version {__version__}", role="muted"))
        titles.addWidget(label("A desktop workbench for Nmap.", wrap=True))
        top.addLayout(titles, 1)
        layout.addLayout(top)
        nmap_text = f"Using {env.version} at {env.executable}" if env and env.usable else "Nmap is not currently available."
        layout.addWidget(label(nmap_text, role="small", wrap=True, selectable=True))
        layout.addWidget(label(
            "Nmap is a separate program by the Nmap Project, distributed under its own license (https://nmap.org/npsl/). "
            "Npcap is a separate product by the Nmap Project. Genmap drives the copies installed on this computer and does not bundle them.",
            role="small",
            wrap=True,
        ))
        layout.addWidget(label("Use Genmap only on networks you own or have written permission to test.", role="small", wrap=True))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class MainWindow(QMainWindow):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.setMinimumSize(980, 640)
        self._window_state = QSettings(str(context.paths.config_dir / "window.ini"), QSettings.Format.IniFormat)

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.sidebar = Sidebar(NAV_ENTRIES)
        root.addWidget(self.sidebar)
        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.dashboard = DashboardPage(context)
        self.new_scan = NewScanPage(context)
        self.monitor = ScanMonitorPage(context)
        self.results = ResultsPage(context)
        self.history = HistoryPage(context)
        self.compare_page = ComparePage(context)
        self.profiles_page = ProfilesPage(context)
        self.targets_page = TargetsPage(context)
        self.nse_page = NsePage(context)
        self.topology_page = TopologyPage(context)
        self.reports_page = ReportsPage(context)
        self.modules = ModulesPage(context)
        self.settings_page = SettingsPage(context)
        self.pages: dict[str, BasePage] = {}
        for page in (self.dashboard, self.new_scan, self.monitor, self.results, self.history, self.compare_page, self.targets_page, self.profiles_page, self.nse_page, self.topology_page, self.reports_page, self.modules, self.settings_page):
            self.pages[page.page_key] = page
            self.stack.addWidget(page)
        self._current_key: Optional[str] = None

        self.sidebar.page_selected.connect(self.show_page)
        self._connect_pages()
        self._build_menus()
        self._build_status_bar()

        context.environment_changed.connect(self._on_environment)
        context.environment_probe_started.connect(lambda: self._set_nmap_status("Checking Nmap...", None))
        context.engine.job_started.connect(self._on_job_started)
        context.engine.job_finished.connect(self._on_job_finished)
        context.settings_changed.connect(self._sync_theme_actions)
        self._restore_window_state()

    # Wiring ---------------------------------------------------------------

    def _connect_pages(self) -> None:
        self.dashboard.quick_scan_requested.connect(self._quick_scan)
        self.dashboard.configure_scan_requested.connect(self._configure_scan)
        self.dashboard.open_run_requested.connect(self.open_run)
        self.dashboard.navigate_requested.connect(self.show_page)
        self.new_scan.scan_started.connect(lambda job: self.show_page("scan_monitor"))
        self.monitor.view_results_requested.connect(self.open_run)
        self.monitor.new_scan_requested.connect(lambda: self.show_page("new_scan"))
        self.results.rerun_requested.connect(self._edit_configuration)
        self.history.open_requested.connect(self.open_run)
        self.history.monitor_requested.connect(lambda _run_id: self.show_page("scan_monitor"))
        self.history.duplicate_requested.connect(self._edit_configuration)
        self.history.rerun_requested.connect(self._rerun_configuration)
        self.profiles_page.use_profile_requested.connect(self._use_profile)
        self.profiles_page.edit_profile_requested.connect(self._use_profile)
        self.targets_page.scan_targets_requested.connect(self._scan_targets)
        self.new_scan.save_targets_requested.connect(self._save_targets_as_group)
        self.nse_page.add_script_requested.connect(self._add_script)
        self.history.report_requested.connect(self.open_reports_for)
        self.history.compare_requested.connect(self.open_comparison)
        self.results.topology_requested.connect(self.open_topology_for)
        self.results.report_requested.connect(self.open_reports_for)

    def _build_menus(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        self._action(file_menu, "&New Scan", "Ctrl+N", lambda: self.show_page("new_scan"))
        self._action(file_menu, "&Import Nmap XML...", "Ctrl+O", self._import_xml)
        file_menu.addSeparator()
        self._action(file_menu, "Open &Data Folder", None, lambda: self._open_folder(self.context.paths.data_dir))
        file_menu.addSeparator()
        self._action(file_menu, "E&xit", QKeySequence.StandardKey.Quit, self.close)

        scan_menu = bar.addMenu("&Scan")
        self._action(scan_menu, "&Start Scan", "Ctrl+Return", self._start_from_menu)
        self._action(scan_menu, "&Inspect Command...", "Ctrl+I", self._inspect_from_menu)
        self.cancel_action = self._action(scan_menu, "&Cancel Running Scan", None, self._cancel_scan)
        self.cancel_action.setEnabled(False)
        scan_menu.addSeparator()
        self._action(scan_menu, "Show &Live Scan", "Ctrl+L", lambda: self.show_page("scan_monitor"))

        view_menu = bar.addMenu("&View")
        shortcuts = {"dashboard": "Ctrl+1", "new_scan": "Ctrl+2", "scan_monitor": "Ctrl+3", "results": "Ctrl+4", "history": "Ctrl+H", "profiles": "Ctrl+P", "settings": "Ctrl+,"}
        for entry in NAV_ENTRIES:
            if entry.key in self.pages:
                self._action(view_menu, entry.title, shortcuts.get(entry.key), lambda _c=False, k=entry.key: self.show_page(k))
        view_menu.addSeparator()
        theme_menu = view_menu.addMenu("&Theme")
        group = QActionGroup(self)
        self._theme_actions: dict[str, QAction] = {}
        for key, text in THEME_CHOICES:
            action = theme_menu.addAction(text)
            action.setCheckable(True)
            action.setChecked(self.context.settings.appearance.theme == key)
            action.triggered.connect(lambda _c=False, k=key: self._set_theme(k))
            group.addAction(action)
            self._theme_actions[key] = action

        help_menu = bar.addMenu("&Help")
        self._action(help_menu, "&Check Nmap Installation", "F5", self.context.refresh_environment)
        self._action(help_menu, "Open &Log Folder", None, lambda: self._open_folder(self.context.paths.log_dir))
        self._action(help_menu, "&Documentation", "F1", lambda: QDesktopServices.openUrl(QUrl(PROJECT_URL)))
        self._action(help_menu, "Nmap &Reference Guide", None, lambda: QDesktopServices.openUrl(QUrl("https://nmap.org/book/man.html")))
        help_menu.addSeparator()
        self._action(help_menu, f"&About {APP_NAME}", None, lambda: AboutDialog(self, self.context.environment).exec())

    def _action(self, menu, text: str, shortcut, slot) -> QAction:
        action = QAction(text, self)
        if shortcut is not None:
            action.setShortcut(QKeySequence(shortcut) if isinstance(shortcut, str) else shortcut)
        action.triggered.connect(slot)
        menu.addAction(action)
        return action

    def _build_status_bar(self) -> None:
        status = self.statusBar()
        status.setSizeGripEnabled(True)
        self.scan_indicator = QPushButton("")
        self.scan_indicator.setProperty("flat", True)
        self.scan_indicator.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_indicator.clicked.connect(lambda: self.show_page("scan_monitor"))
        self.scan_indicator.hide()
        status.addPermanentWidget(self.scan_indicator)
        self.nmap_status = QPushButton("Checking Nmap...")
        self.nmap_status.setProperty("flat", True)
        self.nmap_status.setCursor(Qt.CursorShape.PointingHandCursor)
        self.nmap_status.setToolTip("Open Nmap settings")
        self.nmap_status.clicked.connect(self._show_nmap_settings)
        status.addPermanentWidget(self.nmap_status)

    def _set_nmap_status(self, text: str, level: Optional[str]) -> None:
        self.nmap_status.setText(text)
        set_status(self.nmap_status, level)

    # Navigation -------------------------------------------------------------

    def open_topology_for(self, run_id: str) -> None:
        self.topology_page.show_runs([run_id])
        self.show_page("topology")

    def open_comparison(self, baseline_id: str, newer_id: str) -> None:
        self.show_page("compare")
        self.compare_page.select_pair(baseline_id, newer_id)

    def show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            return
        if self._current_key == key and self.stack.currentWidget() is page:
            return
        previous = self.pages.get(self._current_key) if self._current_key else None
        if previous is not None:
            previous.on_hidden()
        self._current_key = key
        self.stack.setCurrentWidget(page)
        self.sidebar.select(key)
        self.setWindowTitle(f"{APP_NAME} | {page.page_title}")
        page.on_shown()
        if key not in ("scan_monitor", "results"):
            self.context.settings.general.last_page = key

    def open_run(self, run_id: str) -> None:
        self.results.show_run(run_id)
        self.show_page("results")

    def _show_nmap_settings(self) -> None:
        self.show_page("settings")
        self.settings_page.show_section("Nmap")

    def _import_xml(self) -> None:
        self.show_page("results")
        self.results.import_xml_dialog()

    def open_xml_file(self, path: Path) -> None:
        self.show_page("results")
        self.results.import_xml(path)

    def _quick_scan(self, targets: str, profile_id) -> None:
        self._configure_scan(targets, profile_id)
        if split_target_text(targets):
            self.new_scan.start_scan()

    def _configure_scan(self, targets: str, profile_id) -> None:
        self.new_scan.apply_profile(profile_id, keep_targets=False)
        self.new_scan.set_targets(targets)
        self.show_page("new_scan")

    def _scan_targets(self, targets: list, exclusions: list) -> None:
        self.new_scan.set_target_spec(targets, exclusions)
        self.show_page("new_scan")

    def _save_targets_as_group(self, targets: list, exclusions: list) -> None:
        self.targets_page.create_group(targets, exclusions, title="Save targets as group")

    def open_reports_for(self, run_id: str) -> None:
        self.show_page("reports")
        self.reports_page.select_scan(run_id)

    def _add_script(self, name: str) -> None:
        added = self.new_scan.add_script(name)
        message = f"Added {name} to the New Scan script selection." if added else f"{name} is already in the New Scan script selection."
        self.statusBar().showMessage(message, 6000)

    def _use_profile(self, profile_id) -> None:
        self.new_scan.apply_profile(profile_id, keep_targets=True)
        self.show_page("new_scan")

    def _edit_configuration(self, config: ScanConfiguration) -> None:
        self.new_scan.load_configuration(config, starting_point="Previous scan")
        self.show_page("new_scan")

    def _rerun_configuration(self, config: ScanConfiguration) -> None:
        self._edit_configuration(config)
        self.new_scan.start_scan()

    def _start_from_menu(self) -> None:
        if self._current_key != "new_scan":
            self.show_page("new_scan")
            return
        self.new_scan.start_scan()

    def _inspect_from_menu(self) -> None:
        if self._current_key != "new_scan":
            self.show_page("new_scan")
        self.new_scan.open_inspector()

    def _cancel_scan(self) -> None:
        self.show_page("scan_monitor")
        self.monitor._confirm_cancel()

    def _set_theme(self, key: str) -> None:
        self.context.settings.appearance.theme = key
        self.context.settings_store.save()
        self.settings_page.sync_theme(key)

    def _sync_theme_actions(self, settings) -> None:
        action = self._theme_actions.get(settings.appearance.theme)
        if action is not None and not action.isChecked():
            action.setChecked(True)

    def _open_folder(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # Events ---------------------------------------------------------------

    def _on_environment(self, env: NmapEnvironment) -> None:
        if not env.usable:
            self._set_nmap_status("Nmap not available", "error")
        elif env.worst_level == DiagnosticLevel.WARNING:
            self._set_nmap_status(f"{env.version}  (warnings)", "warning")
        else:
            self._set_nmap_status(str(env.version), "ok")
        if not env.usable and self.context.settings.general.check_environment_on_startup and not getattr(self, "_warned_missing", False):
            self._warned_missing = True
            first = next((d for d in env.diagnostics if d.level == DiagnosticLevel.ERROR), None)
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Nmap is required")
            box.setText(first.title if first else "Nmap is not available.")
            box.setInformativeText(
                ((first.detail + "\n\n") if first and first.detail else "")
                + (first.remedy if first and first.remedy else "Install Nmap or set its location in Settings.")
            )
            settings_button = box.addButton("Open Nmap settings", QMessageBox.ButtonRole.AcceptRole)
            box.addButton("Later", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() is settings_button:
                self._show_nmap_settings()

    def _on_job_started(self, job: ScanJob) -> None:
        self.monitor.attach(job)
        self.cancel_action.setEnabled(True)
        self.scan_indicator.setText(f"Scanning {job.record.target_summary}")
        set_status(self.scan_indicator, "info")
        self.scan_indicator.show()
        self.statusBar().showMessage("Scan started.", 4000)

    def _on_job_finished(self, job: ScanJob) -> None:
        running = self.context.engine.active_jobs
        self.cancel_action.setEnabled(bool(running))
        if running:
            self.scan_indicator.setText(f"Scanning {running[0].record.target_summary}")
        else:
            self.scan_indicator.hide()
        record = job.record
        self.statusBar().showMessage(f"Scan of {record.target_summary}: {record.status.label}.", 10000)
        if not self.isActiveWindow():
            QApplication.alert(self)

    def _restore_window_state(self) -> None:
        geometry = self._window_state.value("geometry")
        if isinstance(geometry, QByteArray) and not geometry.isEmpty():
            self.restoreGeometry(geometry)
        else:
            screen = QApplication.primaryScreen()
            if screen is not None:
                available = screen.availableGeometry()
                width = min(1360, int(available.width() * 0.9))
                height = min(880, int(available.height() * 0.9))
                self.resize(max(width, self.minimumWidth()), max(height, self.minimumHeight()))
                self.move(available.center().x() - self.width() // 2, available.center().y() - self.height() // 2)

    def start(self) -> None:
        settings = self.context.settings.general
        key = settings.last_page if settings.restore_last_page and settings.last_page in self.pages else "dashboard"
        self.show_page(key)

    def closeEvent(self, event: QCloseEvent) -> None:
        active = self.context.engine.active_jobs
        if active:
            answer = QMessageBox.question(
                self,
                "Scan in progress",
                "A scan is still running. Stop it and exit? Hosts already finished are kept as partial results.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        if self.targets_page.has_unsaved_changes():
            answer = QMessageBox.question(
                self,
                "Unsaved target group",
                "Save the changes to the open target group before exiting?",
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Save,
            )
            if answer == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return
            if answer == QMessageBox.StandardButton.Save and not self.targets_page._save():
                event.ignore()
                return
        if self.settings_page.has_unsaved_changes():
            answer = QMessageBox.question(
                self,
                "Unsaved settings",
                "Save the changes made on the Settings page before exiting?",
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Save,
            )
            if answer == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return
            if answer == QMessageBox.StandardButton.Save and not self.settings_page.save():
                event.ignore()
                return
        self._window_state.setValue("geometry", self.saveGeometry())
        self._window_state.sync()
        try:
            self.context.settings_store.save()
        except Exception:
            log.warning("Settings could not be saved on exit", exc_info=True)
        for job in active:
            job.cancel()
            job._process.waitForFinished(3000)
        self.context.shutdown()
        event.accept()
