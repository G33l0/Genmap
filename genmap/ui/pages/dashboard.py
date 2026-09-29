"""Dashboard: environment status, quick launch, and recent activity."""

from __future__ import annotations

import logging
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCompleter,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from genmap import __version__
from genmap.core.diagnostics import DiagnosticLevel
from genmap.engine.run_store import RunStatus
from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.npcap import CaptureDriverStatus
from genmap.nmap.privileges import privilege_label
from genmap.resources import logo_pixmap
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import ScrollPage
from genmap.ui.pages.history import status_label
from genmap.ui.pages.scan_monitor import format_duration
from genmap.ui.widgets.common import Card, KeyValueGrid, Metric, label, set_status
from genmap.ui.widgets.inputs import EnumCombo, TextField
from genmap.ui.widgets.responsive import ResponsiveGrid

log = logging.getLogger(__name__)

_LEVEL_STATUS = {
    DiagnosticLevel.OK: "ok",
    DiagnosticLevel.INFO: "ok",
    DiagnosticLevel.WARNING: "warning",
    DiagnosticLevel.ERROR: "error",
}


class DashboardPage(ScrollPage):
    page_key = "dashboard"
    page_title = "Dashboard"

    quick_scan_requested = pyqtSignal(str, object)  # targets, profile id or None
    configure_scan_requested = pyqtSignal(str, object)
    open_run_requested = pyqtSignal(str)
    navigate_requested = pyqtSignal(str)

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        layout = self.layout_

        hero = QHBoxLayout()
        hero.setSpacing(16)
        self.logo = QLabel()
        self.logo.setFixedSize(56, 56)
        hero.addWidget(self.logo, 0, Qt.AlignmentFlag.AlignTop)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(label("Genmap", role="title"))
        titles.addWidget(label("Plan, run, and review Nmap scans with the full engine behind a clear desktop workflow.", role="subtitle", wrap=True))
        hero.addLayout(titles, 1)
        layout.addLayout(hero)

        self.grid = ResponsiveGrid({0: 1, 980: 2})
        layout.addWidget(self.grid)

        self.quick_card = Card("Quick scan")
        self.quick_targets = TextField("Targets, e.g. 192.168.1.0/24 or scanme.nmap.org", mono=True)
        self.quick_targets.setAccessibleName("Quick scan targets")
        self.quick_targets.returnPressed.connect(self._quick_scan)
        self.quick_card.add_widget(self.quick_targets)
        quick_row = QHBoxLayout()
        self.quick_preset = EnumCombo([])
        self.quick_preset.setToolTip("Profile to scan with")
        self.quick_preset.currentIndexChanged.connect(self._update_preset_hint)
        quick_row.addWidget(self.quick_preset, 1)
        self.configure_button = QPushButton("Configure...")
        self.configure_button.setToolTip("Open these targets in New Scan to adjust options first")
        self.configure_button.clicked.connect(self._configure)
        self.quick_button = QPushButton("Review and start")
        self.quick_button.setProperty("accent", True)
        self.quick_button.clicked.connect(self._quick_scan)
        quick_row.addWidget(self.configure_button)
        quick_row.addWidget(self.quick_button)
        self.quick_card.add_layout(quick_row)
        self.preset_hint = label("", role="small", wrap=True)
        self.quick_card.add_widget(self.preset_hint)
        self.quick_card.add_widget(label("Only scan networks and hosts you own or are authorized to test.", role="small", wrap=True))
        self.quick_card.add_stretch()
        self._descriptions: dict[object, str] = {}
        self._load_profiles()
        self.grid.add(self.quick_card)

        self.env_card = Card("Nmap environment", actions=[self._link_button("Details", lambda: self.navigate_requested.emit("settings"))])
        self.env_status = label("Checking the Nmap installation...", role="section", wrap=True)
        self.env_card.add_widget(self.env_status)
        self.env_grid = KeyValueGrid()
        self.env_grid.add_row("Nmap")
        self.env_grid.add_row("Location", mono=True)
        self.env_grid.add_row("Packet capture")
        self.env_grid.add_row("Privileges")
        self.env_grid.add_row("NSE scripts")
        self.env_card.add_widget(self.env_grid)
        self.env_problem = label("", wrap=True, selectable=True)
        self.env_card.add_widget(self.env_problem)
        self.env_card.add_stretch()
        self.grid.add(self.env_card)

        self.last_card = Card("Last scan", actions=[self._link_button("History", lambda: self.navigate_requested.emit("history"))])
        self.last_title = label("No scans yet.", role="section", wrap=True)
        self.last_card.add_widget(self.last_title)
        self.last_detail = label("", role="muted", wrap=True)
        self.last_card.add_widget(self.last_detail)
        metrics = QGridLayout()
        metrics.setSpacing(10)
        self.last_hosts = Metric("Hosts up", "-")
        self.last_ports = Metric("Open ports", "-")
        self.last_services = Metric("Identified services", "-")
        self.last_services.setToolTip("Services confirmed by Nmap's version detection.")
        for column, metric in enumerate((self.last_hosts, self.last_ports, self.last_services)):
            metrics.addWidget(metric, 0, column)
        self.last_card.add_layout(metrics)
        self.last_open = QPushButton("Open results")
        self.last_open.clicked.connect(self._open_last)
        self.last_card.add_widget(self.last_open, 0)
        self.last_card.add_stretch()
        self._last_run_id: Optional[str] = None
        self.grid.add(self.last_card)

        self.recent_card = Card("Recent scans")
        self.recent_box = QVBoxLayout()
        self.recent_box.setSpacing(4)
        self.recent_card.add_layout(self.recent_box)
        self.recent_card.add_stretch()
        self.grid.add(self.recent_card)

        self.library_card = Card("Library")
        library = QGridLayout()
        library.setSpacing(10)
        self.lib_profiles = Metric("Saved profiles", "-")
        self.lib_groups = Metric("Target groups", "-")
        self.lib_hosts = Metric("Known hosts", "-")
        self.lib_hosts.setToolTip("Distinct addresses Nmap reported as up across all indexed scans.")
        self.lib_scans = Metric("Scans stored", "-")
        for column, metric in enumerate((self.lib_profiles, self.lib_groups, self.lib_hosts, self.lib_scans)):
            library.addWidget(metric, 0, column)
        self.library_card.add_layout(library)
        links = QHBoxLayout()
        for text, key in (("Profiles", "profiles"), ("Targets", "targets"), ("NSE scripts", "nse"), ("Reports", "reports")):
            links.addWidget(self._link_button(text, lambda _c=False, k=key: self.navigate_requested.emit(k)))
        links.addStretch(1)
        self.library_card.add_layout(links)
        self.grid.add(self.library_card, span=2)

        self.health_card = Card("Application")
        self.health = KeyValueGrid()
        self.health.add_row("Version", __version__)
        self.health.add_row("Data folder", str(context.paths.data_dir), mono=True)
        self.health.add_row("Modules")
        self.health.add_row("Settings")
        self.health_card.add_widget(self.health)
        self.grid.add(self.health_card, span=2)
        layout.addStretch(1)

        context.environment_changed.connect(self._show_environment)
        context.environment_probe_started.connect(self._probe_started)
        context.index_changed.connect(self._refresh_if_visible)
        context.profiles_changed.connect(self._load_profiles)
        context.profiles_changed.connect(self._refresh_if_visible)
        context.target_groups_changed.connect(self._refresh_if_visible)

    def _link_button(self, text: str, slot) -> QPushButton:
        button = QPushButton(text)
        button.setProperty("flat", True)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.clicked.connect(slot)
        return button

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.logo.setPixmap(logo_pixmap(56, self.devicePixelRatioF()))

    def _refresh_if_visible(self) -> None:
        if self.isVisible():
            self._refresh_runs()

    def _load_profiles(self) -> None:
        current = self.quick_preset.current_value() if self.quick_preset.count() else "unset"
        try:
            profiles = self.context.profiles.list()
        except Exception:
            profiles = []
        self.quick_preset.blockSignals(True)
        self.quick_preset.clear()
        self._descriptions = {None: "Nmap's defaults: the top 1000 TCP ports with its default technique."}
        self.quick_preset.addItem("No profile (Nmap defaults)", None)
        for profile in profiles:
            self.quick_preset.addItem(profile.name, profile.id)
            self._descriptions[profile.id] = profile.description
        if current == "unset":
            default = next((p.id for p in profiles if p.builtin_key == "default"), None)
            self.quick_preset.set_current_value(default)
        else:
            self.quick_preset.set_current_value(current)
        self.quick_preset.blockSignals(False)
        self._update_preset_hint()

    def on_shown(self) -> None:
        self._refresh_runs()
        recent = list(self.context.settings.general.recent_targets)
        try:
            recent += [t for t, _when, _count in self.context.scan_index.recent_targets(limit=50) if t not in recent]
        except Exception:
            pass
        completer = QCompleter(recent, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.quick_targets.setCompleter(completer)
        if not self.quick_targets.text() and recent:
            self.quick_targets.setPlaceholderText(f"Targets, e.g. {recent[0]}")
        if self.context.environment is not None:
            self._show_environment(self.context.environment)
        modules = list(self.context.registry)
        self.health.set_value("Modules", ", ".join(f"{m.manifest.name} ({m.state.value})" for m in modules))
        problem = self.context.settings_store.load_problem
        self.health.set_value("Settings", problem.message if problem else f"Loaded from {self.context.paths.settings_file}", status="warning" if problem else None)
        self.quick_targets.setFocus()

    def _update_preset_hint(self) -> None:
        self.preset_hint.setText(self._descriptions.get(self.quick_preset.current_value(), ""))

    def _quick_scan(self) -> None:
        self.quick_scan_requested.emit(self.quick_targets.text().strip(), self.quick_preset.current_value())

    def _configure(self) -> None:
        self.configure_scan_requested.emit(self.quick_targets.text().strip(), self.quick_preset.current_value())

    def _probe_started(self) -> None:
        self.env_status.setText("Checking the Nmap installation...")
        set_status(self.env_status, None)

    def _show_environment(self, env: NmapEnvironment) -> None:
        worst = env.worst_level
        if not env.usable:
            self.env_status.setText("Nmap is not ready")
        elif worst == DiagnosticLevel.WARNING:
            self.env_status.setText("Nmap is ready, with warnings")
        else:
            self.env_status.setText("Nmap is ready")
        set_status(self.env_status, _LEVEL_STATUS[worst] if env.usable else "error")
        self.env_grid.set_value("Nmap", str(env.version) if env.version else "Not found", status=None if env.version else "error")
        self.env_grid.set_value("Location", str(env.executable) if env.executable else "")
        driver = env.capture_driver
        if driver is None:
            capture = "Unknown"
            capture_status = None
        elif driver.status == CaptureDriverStatus.DETECTED:
            capture, capture_status = f"{driver.name} {driver.version or ''} detected".strip(), "ok"
        elif driver.status == CaptureDriverStatus.MISSING:
            capture, capture_status = "Npcap not detected", "warning"
        elif driver.status == CaptureDriverStatus.LEGACY:
            capture, capture_status = "Legacy WinPcap", "warning"
        else:
            capture, capture_status = driver.detail or driver.name, None
        self.env_grid.set_value("Packet capture", capture, status=capture_status)
        self.env_grid.set_value("Privileges", privilege_label(env.privileges))
        count = len(env.scripts.scripts)
        self.env_grid.set_value("NSE scripts", f"{count} installed" if count else "Not found", status=None if count else "warning")
        problems = [d for d in env.diagnostics if d.level in (DiagnosticLevel.ERROR, DiagnosticLevel.WARNING)]
        if problems:
            first = problems[0]
            self.env_problem.setText(f"{first.title}. {first.remedy or first.detail}")
            set_status(self.env_problem, "error" if first.level == DiagnosticLevel.ERROR else "warning")
            self.env_problem.show()
        else:
            self.env_problem.hide()
        self.quick_button.setEnabled(env.usable)
        self.quick_button.setToolTip("" if env.usable else "Nmap is not available. See Settings, Nmap.")

    def _refresh_runs(self) -> None:
        try:
            scans = self.context.scan_index.list_scans(limit=6)
            stats = self.context.scan_index.stats()
            profile_count = len(self.context.profiles.list())
            group_count = len(self.context.target_groups.list())
        except Exception:
            log.exception("Dashboard data could not be loaded")
            return
        self.lib_profiles.set_value(str(profile_count))
        self.lib_groups.set_value(str(group_count))
        self.lib_hosts.set_value(str(stats.distinct_hosts))
        self.lib_scans.set_value(str(stats.scans))
        while self.recent_box.count():
            item = self.recent_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not scans:
            self.recent_box.addWidget(label("Scans you run will be listed here.", role="muted"))
        for scan in scans:
            when = scan.created_at.astimezone().strftime("%b %d %H:%M")
            row = QPushButton(f"{when}   {scan.target_summary}   \u2022  {status_label(scan.status)}")
            row.setProperty("flat", True)
            row.setStyleSheet("text-align: left;")
            row.setCursor(Qt.CursorShape.PointingHandCursor)
            row.setToolTip(scan.command_display or "")
            row.setEnabled(not scan.folder_missing)
            row.clicked.connect(lambda _checked=False, run_id=scan.run_id: self.open_run_requested.emit(run_id))
            self.recent_box.addWidget(row)

        terminal = {s.value for s in RunStatus if s.is_terminal}
        finished = next((s for s in scans if s.status in terminal and not s.folder_missing), None)
        self._last_run_id = finished.run_id if finished else None
        self.last_open.setEnabled(finished is not None)
        if finished is None:
            self.last_title.setText("No completed scans yet.")
            self.last_detail.setText("Run a quick scan to see a summary here.")
            for metric in (self.last_hosts, self.last_ports, self.last_services):
                metric.set_value("-")
            set_status(self.last_title, None)
            return
        self.last_title.setText(finished.target_summary)
        parts = [status_label(finished.status), finished.created_at.astimezone().strftime("%Y-%m-%d %H:%M")]
        if finished.started_at and finished.finished_at:
            parts.append(f"took {format_duration((finished.finished_at - finished.started_at).total_seconds())}")
        if finished.profile_name:
            parts.append(finished.profile_name)
        self.last_detail.setText("  \u2022  ".join(parts))
        has_counts = finished.results_indexed or finished.hosts_total
        self.last_hosts.set_value(f"{finished.hosts_up}/{finished.hosts_total}" if has_counts else "-")
        self.last_ports.set_value(str(finished.open_ports) if has_counts else "-")
        self.last_services.set_value(str(finished.services) if has_counts else "-")
        failed = {RunStatus.FAILED.value, RunStatus.CRASHED.value}
        set_status(self.last_title, "error" if finished.status in failed else None)

    def _open_last(self) -> None:
        if self._last_run_id:
            self.open_run_requested.emit(self._last_run_id)
