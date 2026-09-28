"""Dashboard: environment status, quick launch, and recent activity."""

from __future__ import annotations

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
from genmap.core.presets import PRESETS, preset_by_key
from genmap.engine.run_store import RunStatus
from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.npcap import CaptureDriverStatus
from genmap.nmap.privileges import privilege_label
from genmap.resources import logo_pixmap
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import ScrollPage
from genmap.ui.pages.scan_monitor import format_duration
from genmap.ui.widgets.common import Card, KeyValueGrid, Metric, label, set_status
from genmap.ui.widgets.inputs import EnumCombo, TextField
from genmap.ui.widgets.responsive import ResponsiveGrid

_LEVEL_STATUS = {
    DiagnosticLevel.OK: "ok",
    DiagnosticLevel.INFO: "ok",
    DiagnosticLevel.WARNING: "warning",
    DiagnosticLevel.ERROR: "error",
}


class DashboardPage(ScrollPage):
    page_key = "dashboard"
    page_title = "Dashboard"

    quick_scan_requested = pyqtSignal(str, str)  # targets, preset key
    configure_scan_requested = pyqtSignal(str, str)
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
        self.quick_preset = EnumCombo([(p.name, p.key) for p in PRESETS])
        for index, preset in enumerate(PRESETS):
            self.quick_preset.setItemData(index, preset.description, Qt.ItemDataRole.ToolTipRole)
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
        self._update_preset_hint()
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
        context.engine.job_finished.connect(lambda _job: self._refresh_runs())
        context.engine.job_started.connect(lambda _job: self._refresh_runs())

    def _link_button(self, text: str, slot) -> QPushButton:
        button = QPushButton(text)
        button.setProperty("flat", True)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.clicked.connect(slot)
        return button

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.logo.setPixmap(logo_pixmap(56, self.devicePixelRatioF()))

    def on_shown(self) -> None:
        self._refresh_runs()
        recent = self.context.settings.general.recent_targets
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
        self.preset_hint.setText(preset_by_key(self.quick_preset.current_value()).description)

    def _quick_scan(self) -> None:
        self.quick_scan_requested.emit(self.quick_targets.text().strip(), str(self.quick_preset.current_value()))

    def _configure(self) -> None:
        self.configure_scan_requested.emit(self.quick_targets.text().strip(), str(self.quick_preset.current_value()))

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
        records = self.context.run_store.list_runs(limit=6)
        while self.recent_box.count():
            item = self.recent_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not records:
            self.recent_box.addWidget(label("Scans you run will be listed here.", role="muted"))
        for record in records:
            row = QPushButton(f"{record.created_at.strftime('%b %d %H:%M')}   {record.target_summary}   •  {record.status.label}")
            row.setProperty("flat", True)
            row.setStyleSheet("text-align: left;")
            row.setCursor(Qt.CursorShape.PointingHandCursor)
            row.setToolTip(record.command.display if record.command else "")
            row.clicked.connect(lambda _checked=False, run_id=record.run_id: self.open_run_requested.emit(run_id))
            self.recent_box.addWidget(row)

        finished = next((r for r in records if r.status.is_terminal), None)
        self._last_run_id = finished.run_id if finished else None
        self.last_open.setEnabled(finished is not None)
        if finished is None:
            self.last_title.setText("No completed scans yet.")
            self.last_detail.setText("Run a quick scan to see a summary here.")
            for metric in (self.last_hosts, self.last_ports, self.last_services):
                metric.set_value("-")
            return
        self.last_title.setText(finished.target_summary)
        duration = finished.duration_seconds
        parts = [finished.status.label, finished.created_at.strftime("%Y-%m-%d %H:%M")]
        if duration is not None:
            parts.append(f"took {format_duration(duration)}")
        if finished.profile_name:
            parts.append(finished.profile_name)
        self.last_detail.setText("  •  ".join(parts))
        summary = finished.summary
        self.last_hosts.set_value(f"{summary.hosts_up}/{summary.hosts_total}" if summary else "-")
        self.last_ports.set_value(str(summary.open_ports) if summary else "-")
        self.last_services.set_value(str(summary.services) if summary else "-")
        set_status(self.last_title, "error" if finished.status in (RunStatus.FAILED, RunStatus.CRASHED) else None)

    def _open_last(self) -> None:
        if self._last_run_id:
            self.open_run_requested.emit(self._last_run_id)
