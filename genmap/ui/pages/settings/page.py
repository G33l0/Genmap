"""Settings page. Edits a working copy of AppSettings and saves on demand."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Optional

from pydantic import ValidationError
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from genmap.logging_setup import ring_buffer
from genmap.nmap.environment import NmapEnvironment
from genmap.settings import AppSettings
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.theme.palettes import THEME_CHOICES
from genmap.ui.widgets.common import Card, KeyValueGrid, PageHeader, form_layout, hint, label
from genmap.ui.widgets.diagnostics_view import DiagnosticsView
from genmap.ui.widgets.error_dialog import show_error
from genmap.ui.widgets.inputs import EnumCombo, TextField

log = logging.getLogger(__name__)

Binding = tuple[Callable[[AppSettings], None], Callable[[AppSettings], None]]  # (load, store)


def _open_folder(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


class _Section(QScrollArea):
    def __init__(self, title: str, subtitle: str = "") -> None:
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        self.layout_ = QVBoxLayout(body)
        self.layout_.setContentsMargins(24, 4, 12, 16)
        self.layout_.setSpacing(14)
        self.layout_.addWidget(PageHeader(title, subtitle))
        self.setWidget(body)
        self.bindings: list[Binding] = []

    def card(self, title: str) -> Card:
        card = Card(title)
        self.layout_.addWidget(card)
        return card

    def finish(self) -> None:
        self.layout_.addStretch(1)


class SettingsPage(BasePage):
    page_key = "settings"
    page_title = "Settings"

    SECTIONS = ["General", "Appearance", "Nmap", "Network", "Scanning", "NSE", "Storage", "Reports", "Logging", "Advanced"]

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._working: AppSettings = context.settings.model_copy(deep=True)
        self._sections: list[_Section] = []
        self._dirty = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader("Settings", "Changes take effect when saved."))

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.nav = QListWidget()
        self.nav.setMaximumWidth(220)
        self.nav.setMinimumWidth(150)
        self.nav.addItems(self.SECTIONS)
        self.nav.setAccessibleName("Settings sections")
        splitter.addWidget(self.nav)
        self.stack = QStackedWidget()
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(1, 1)
        outer.addWidget(splitter, 1)

        builders = [
            self._general,
            self._appearance,
            self._nmap,
            self._network,
            self._scanning,
            self._nse,
            self._storage,
            self._reports,
            self._logging,
            self._advanced,
        ]
        for build in builders:
            section = build()
            section.finish()
            self._sections.append(section)
            self.stack.addWidget(section)
            self._watch(section)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        footer = QHBoxLayout()
        self.footer_note = label("", role="muted")
        footer.addWidget(self.footer_note, 1)
        self.revert_button = QPushButton("Revert")
        self.revert_button.clicked.connect(self.revert)
        self.defaults_button = QPushButton("Restore defaults")
        self.defaults_button.clicked.connect(self._restore_defaults)
        self.save_button = QPushButton("Save")
        self.save_button.setProperty("accent", True)
        self.save_button.clicked.connect(self.save)
        for button in (self.defaults_button, self.revert_button, self.save_button):
            footer.addWidget(button)
        outer.addLayout(footer)

        context.environment_changed.connect(self._show_environment)
        context.environment_probe_started.connect(lambda: self.nmap_status.setText("Checking..."))
        self.revert()

    def show_section(self, name: str) -> None:
        if name in self.SECTIONS:
            self.nav.setCurrentRow(self.SECTIONS.index(name))

    def on_shown(self) -> None:
        if not self._dirty:
            self.revert()
        if self.context.environment is not None:
            self._show_environment(self.context.environment)
        self._refresh_log_view()
        self._refresh_storage()

    def _watch(self, section: _Section) -> None:
        widget = section.widget()
        for w in widget.findChildren(QLineEdit):
            w.textEdited.connect(self._mark_dirty)
        for w in widget.findChildren(QSpinBox):
            w.valueChanged.connect(self._mark_dirty)
        for w in widget.findChildren(QComboBox):
            w.activated.connect(self._mark_dirty)
        for w in widget.findChildren(QCheckBox):
            w.clicked.connect(self._mark_dirty)

    def _mark_dirty(self, *_args) -> None:
        self._dirty = True
        self.footer_note.setText("Unsaved changes.")

    def revert(self) -> None:
        self._working = self.context.settings.model_copy(deep=True)
        for section in self._sections:
            for load, _store in section.bindings:
                load(self._working)
        self._dirty = False
        self.footer_note.setText("")

    def _restore_defaults(self) -> None:
        answer = QMessageBox.question(
            self,
            "Restore defaults",
            "Reset every setting to its default value? The Nmap path and recent targets are cleared as well. Nothing is saved until you click Save.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._working = AppSettings()
        for section in self._sections:
            for load, _store in section.bindings:
                load(self._working)
        self._mark_dirty()

    def save(self) -> bool:
        data = self._working.model_dump()
        candidate = AppSettings.model_validate(data)
        try:
            for section in self._sections:
                for _load, store in section.bindings:
                    store(candidate)
            candidate = AppSettings.model_validate(candidate.model_dump())
        except (ValidationError, ValueError) as exc:
            show_error(self, "Settings not saved", "One of the values is not valid.", "Correct the highlighted value and save again.", str(exc))
            return False
        old_nmap = (self.context.settings.nmap.executable_path, self.context.settings.nmap.data_directory)
        recent = self.context.settings.general.recent_targets
        candidate.general.recent_targets = recent
        candidate.general.last_page = self.context.settings.general.last_page
        try:
            self.context.settings_store.replace(candidate)
        except Exception as exc:
            from genmap.ui.widgets.error_dialog import show_exception

            show_exception(self, exc, "Settings not saved")
            return False
        self._working = candidate.model_copy(deep=True)
        self._dirty = False
        self.footer_note.setText("Saved.")
        if (candidate.nmap.executable_path, candidate.nmap.data_directory) != old_nmap:
            self.context.refresh_environment()
        return True

    def sync_theme(self, key: str) -> None:
        """Reflect a theme chosen elsewhere without discarding other unsaved edits."""
        self._working.appearance.theme = key
        self.theme_combo.set_current_value(key)

    def has_unsaved_changes(self) -> bool:
        return self._dirty

    # Binding helpers ------------------------------------------------------

    def _bind_check(self, section: _Section, widget: QCheckBox, group: str, name: str) -> None:
        section.bindings.append((
            lambda s: widget.setChecked(bool(getattr(getattr(s, group), name))),
            lambda s: setattr(getattr(s, group), name, widget.isChecked()),
        ))

    def _bind_spin(self, section: _Section, widget: QSpinBox, group: str, name: str) -> None:
        section.bindings.append((
            lambda s: widget.setValue(int(getattr(getattr(s, group), name))),
            lambda s: setattr(getattr(s, group), name, widget.value()),
        ))

    def _bind_text(self, section: _Section, widget: QLineEdit, group: str, name: str, *, optional: bool = True) -> None:
        def store(s: AppSettings) -> None:
            text = widget.text().strip()
            setattr(getattr(s, group), name, (text or None) if optional else text)

        section.bindings.append((lambda s: widget.setText(getattr(getattr(s, group), name) or ""), store))

    def _bind_combo(self, section: _Section, widget: EnumCombo, group: str, name: str) -> None:
        section.bindings.append((
            lambda s: widget.set_current_value(getattr(getattr(s, group), name)),
            lambda s: setattr(getattr(s, group), name, widget.current_value()),
        ))

    def _path_row(self, field: QLineEdit, *, directory: bool, caption: str, file_filter: str = "All files (*)") -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(field, 1)
        button = QPushButton("Browse...")

        def browse() -> None:
            start = field.text() or str(Path.home())
            if directory:
                path = QFileDialog.getExistingDirectory(self, caption, start)
            else:
                path, _ = QFileDialog.getOpenFileName(self, caption, start, file_filter)
            if path:
                field.setText(path)
                self._mark_dirty()

        button.clicked.connect(browse)
        layout.addWidget(button)
        return row

    # Sections ---------------------------------------------------------------

    def _general(self) -> _Section:
        section = _Section("General")
        card = section.card("Safety")
        for text, name in (
            ("Always show a confirmation with the command before starting a scan", "confirm_intrusive_scans"),
            ("Ask before cancelling a running scan", "confirm_scan_cancel"),
        ):
            box = QCheckBox(text)
            card.add_widget(box)
            self._bind_check(section, box, "general", name)
        card.add_widget(hint("Scans that use intrusive NSE categories, spoofing, or random Internet targets are always confirmed."))
        card = section.card("Startup")
        for text, name in (
            ("Check the Nmap installation when Genmap starts", "check_environment_on_startup"),
            ("Reopen the page that was open when Genmap closed", "restore_last_page"),
        ):
            box = QCheckBox(text)
            card.add_widget(box)
            self._bind_check(section, box, "general", name)
        clear = QPushButton("Clear recent targets")
        clear.clicked.connect(self._clear_recent_targets)
        card.add_widget(clear, 0)
        return section

    def _clear_recent_targets(self) -> None:
        self.context.settings.general.recent_targets = []
        self.context.settings_store.save()
        self.footer_note.setText("Recent targets cleared.")

    def _appearance(self) -> _Section:
        section = _Section("Appearance")
        card = section.card("Theme")
        form = form_layout()
        theme = EnumCombo([(caption, key) for key, caption in THEME_CHOICES])
        theme.setToolTip("Hacker is a black and green terminal style theme with a monospace interface font.")
        self.theme_combo = theme
        form.addRow("Theme", theme)
        self._bind_combo(section, theme, "appearance", "theme")
        size = QSpinBox()
        size.setRange(8, 16)
        size.setSuffix(" pt")
        form.addRow("Base font size", size)
        self._bind_spin(section, size, "appearance", "base_font_size")
        mono = TextField("Comma separated font families")
        form.addRow("Monospace fonts", mono)
        self._bind_text(section, mono, "appearance", "monospace_font_family", optional=False)
        card.add_layout(form)
        return section

    def _nmap(self) -> _Section:
        section = _Section("Nmap", "Genmap runs the Nmap installed on this computer. It does not include its own copy.")
        card = section.card("Executable")
        form = form_layout()
        self.nmap_path = TextField("Detect automatically")
        filter_ = "Nmap (nmap.exe);;Programs (*.exe);;All files (*)" if Path("C:/").exists() else "All files (*)"
        form.addRow("Nmap executable", self._path_row(self.nmap_path, directory=False, caption="Select the Nmap executable", file_filter=filter_))
        self._bind_text(section, self.nmap_path, "nmap", "executable_path")
        self.nmap_data = TextField("Detect automatically")
        form.addRow("Data directory", self._path_row(self.nmap_data, directory=True, caption="Select the Nmap data directory"))
        self._bind_text(section, self.nmap_data, "nmap", "data_directory")
        timeout = QSpinBox()
        timeout.setRange(5, 120)
        timeout.setSuffix(" s")
        form.addRow("Probe timeout", timeout)
        self._bind_spin(section, timeout, "nmap", "probe_timeout_seconds")
        card.add_layout(form)
        row = QHBoxLayout()
        recheck = QPushButton("Save and check again")
        recheck.setProperty("accent", True)
        recheck.clicked.connect(self._save_and_probe)
        row.addWidget(recheck)
        download = QPushButton("Get Nmap...")
        download.setToolTip("https://nmap.org/download.html")
        download.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://nmap.org/download.html")))
        row.addWidget(download)
        row.addStretch(1)
        card.add_layout(row)
        self.nmap_status = label("", role="muted", wrap=True)
        card.add_widget(self.nmap_status)

        card = section.card("Installation")
        self.nmap_summary = KeyValueGrid()
        for key in ("Version", "Location", "Found via", "Data directory", "Platform", "Compiled with", "Packet capture", "Privileges"):
            self.nmap_summary.add_row(key, mono=key in ("Location", "Data directory"))
        card.add_widget(self.nmap_summary)

        card = section.card("Diagnostics")
        self.diagnostics = DiagnosticsView()
        card.add_widget(self.diagnostics)

        card = section.card("Capabilities")
        card.add_widget(hint("Derived from the version, build libraries, packet capture driver, and privileges. Nmap has the final say when a scan runs."))
        self.capabilities = QTableWidget(0, 3)
        self.capabilities.setHorizontalHeaderLabels(["Capability", "Available", "Detail"])
        self.capabilities.verticalHeader().setVisible(False)
        self.capabilities.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.capabilities.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.capabilities.setWordWrap(True)
        self.capabilities.setMinimumHeight(260)
        card.add_widget(self.capabilities)
        return section

    def _network(self) -> _Section:
        section = _Section("Network", "Interfaces as reported by nmap --iflist.")
        card = section.card("Interfaces")
        self.interfaces = QTableWidget(0, 6)
        self.interfaces.setHorizontalHeaderLabels(["Device", "Name", "Address", "Type", "State", "MAC"])
        self.interfaces.verticalHeader().setVisible(False)
        self.interfaces.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.interfaces.horizontalHeader().setStretchLastSection(True)
        self.interfaces.setMinimumHeight(180)
        card.add_widget(self.interfaces)
        card = section.card("Routes")
        self.routes = QTableWidget(0, 4)
        self.routes.setHorizontalHeaderLabels(["Destination", "Device", "Metric", "Gateway"])
        self.routes.verticalHeader().setVisible(False)
        self.routes.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.routes.horizontalHeader().setStretchLastSection(True)
        self.routes.setMinimumHeight(160)
        card.add_widget(self.routes)
        return section

    def _scanning(self) -> _Section:
        section = _Section("Scanning")
        card = section.card("Execution")
        form = form_layout()
        interval = TextField("e.g. 2s")
        interval.setToolTip("Passed to Nmap as --stats-every so the live view can show progress.")
        form.addRow("Progress interval", interval)
        self._bind_text(section, interval, "scanning", "stats_interval", optional=False)
        inject = QCheckBox("Ask Nmap for periodic progress reports")
        form.addRow("", inject)
        self._bind_check(section, inject, "scanning", "inject_stats_interval")
        timeout = QSpinBox()
        timeout.setRange(0, 7 * 24 * 60)
        timeout.setSpecialValueText("No limit")
        timeout.setSuffix(" min")
        form.addRow("Stop scans after", timeout)
        self._bind_spin(section, timeout, "scanning", "scan_timeout_minutes")
        verbosity = QSpinBox()
        verbosity.setRange(0, 4)
        verbosity.setToolTip("Verbosity for new scans. Level 1 reports ports as they are found.")
        form.addRow("Default verbosity", verbosity)
        self._bind_spin(section, verbosity, "scanning", "default_verbosity")
        card.add_layout(form)
        card = section.card("Output")
        form = form_layout()
        keep = QCheckBox("Save Nmap console output with each scan")
        form.addRow("", keep)
        self._bind_check(section, keep, "scanning", "keep_stdout_log")
        lines = QSpinBox()
        lines.setRange(1000, 500000)
        lines.setSingleStep(1000)
        lines.setSuffix(" lines")
        form.addRow("Live console limit", lines)
        self._bind_spin(section, lines, "scanning", "output_buffer_lines")
        card.add_layout(form)
        return section

    def _nse(self) -> _Section:
        section = _Section("NSE")
        card = section.card("Intrusive script warnings")
        card.add_widget(hint(
            "Before a scan starts, Genmap resolves the script selection against the installed script database "
            "and lists every selected script that Nmap files under one of these categories. The warning cannot be turned off."
        ))
        form = form_layout()
        categories = TextField("Comma separated")
        form.addRow("Intrusive categories", categories)
        section.bindings.append((
            lambda s: categories.setText(", ".join(s.nse.intrusive_categories)),
            lambda s: setattr(s.nse, "intrusive_categories", [c.strip().lower() for c in categories.text().split(",") if c.strip()]),
        ))
        timeout = TextField("e.g. 5m")
        form.addRow("Default script timeout", timeout)
        self._bind_text(section, timeout, "nse", "default_script_timeout")
        card.add_layout(form)
        card.add_widget(hint("Categories come from Nmap's own classification. A script outside them is not guaranteed to be harmless."))
        return section

    def _storage(self) -> _Section:
        section = _Section("Storage")
        card = section.card("Locations")
        self.storage_grid = KeyValueGrid()
        paths = self.context.paths
        for key, path in (
            ("Scans", paths.scans_dir),
            ("Database", paths.database_file),
            ("Settings", paths.config_dir),
            ("Logs", paths.log_dir),
            ("Data", paths.data_dir),
        ):
            self.storage_grid.add_row(key, str(path), mono=True)
        card.add_widget(self.storage_grid)
        row = QHBoxLayout()
        for text, path in (("Open scans folder", paths.scans_dir), ("Open data folder", paths.data_dir)):
            button = QPushButton(text)
            button.clicked.connect(lambda _c=False, p=path: _open_folder(p))
            row.addWidget(button)
        row.addStretch(1)
        card.add_layout(row)
        card.add_widget(hint("Set the GENMAP_HOME environment variable to keep all Genmap data in one folder, for example on a portable drive."))

        card = section.card("Scan index")
        card.add_widget(hint(
            "Each scan folder keeps the raw Nmap XML, console output, and configuration; these are never discarded. "
            "The database indexes them for history, search, and reports, and can always be rebuilt from the folders."
        ))
        row = QHBoxLayout()
        self.rebuild_button = QPushButton("Rebuild scan index")
        self.rebuild_button.setToolTip("Read every scan folder again and refresh the database")
        self.rebuild_button.clicked.connect(self._rebuild_index)
        self.check_button = QPushButton("Check database")
        self.check_button.clicked.connect(self._check_database)
        row.addWidget(self.rebuild_button)
        row.addWidget(self.check_button)
        row.addStretch(1)
        card.add_layout(row)
        self.index_status = label("", role="muted", wrap=True)
        card.add_widget(self.index_status)
        self.context.index_changed.connect(self._on_index_changed)
        return section

    def _refresh_storage(self) -> None:
        size = self.context.run_store.total_size_bytes() / 1_000_000
        self.storage_grid.set_value("Scans", f"{self.context.paths.scans_dir}  ({size:.1f} MB)")
        db_size = self.context.database.size_bytes() / 1_000_000
        revision = self.context.database.current_revision() or "none"
        self.storage_grid.set_value("Database", f"{self.context.paths.database_file}  ({db_size:.1f} MB, schema {revision})")
        stats = self.context.scan_index.stats()
        self.index_status.setText(f"{stats.scans} scans indexed, {stats.distinct_hosts} distinct hosts seen up, {stats.open_port_observations} open port observations.")

    def _rebuild_index(self) -> None:
        self.rebuild_button.setEnabled(False)
        self.index_status.setText("Rebuilding the scan index...")
        self._rebuilding = True
        self.context.scan_index.mark_all_for_reindex()
        self.context.reconcile_index()

    def _on_index_changed(self) -> None:
        if getattr(self, "_rebuilding", False):
            self._rebuilding = False
            self.rebuild_button.setEnabled(True)
        if self.isVisible():
            self._refresh_storage()

    def _check_database(self) -> None:
        try:
            ok = self.context.database.integrity_ok()
        except Exception as exc:
            ok = False
            detail = str(exc)
        else:
            detail = ""
        if ok:
            QMessageBox.information(self, "Database check", "The database passed SQLite's integrity check.")
        else:
            show_error(
                self,
                "Database check",
                "The database failed SQLite's integrity check.",
                "Close Genmap and start it again; a damaged database is set aside and the scan index rebuilt from the scan folders.",
                detail,
            )

    def _reports(self) -> _Section:
        section = _Section("Reports")
        card = section.card("Defaults")
        form = form_layout()
        fmt = EnumCombo([("HTML report", "html"), ("JSON data", "json"), ("CSV, one row per port", "csv"), ("Original Nmap XML", "xml")])
        form.addRow("Default format", fmt)
        self._bind_combo(section, fmt, "reports", "default_format")
        folder = TextField("Documents\\Genmap Reports")
        form.addRow("Report folder", self._path_row(folder, directory=True, caption="Default report folder"))
        self._bind_text(section, folder, "reports", "default_output_directory")
        card.add_layout(form)
        card.add_widget(hint("Used by the Reports page and by exports from the Results page."))
        return section

    def _logging(self) -> _Section:
        section = _Section("Logging", "Genmap writes its own activity log. Nmap output is stored with each scan.")
        card = section.card("Log level")
        form = form_layout()
        level = EnumCombo([("Errors only", "ERROR"), ("Warnings", "WARNING"), ("Information", "INFO"), ("Debug", "DEBUG")])
        form.addRow("Level", level)
        self._bind_combo(section, level, "logging", "level")
        card.add_layout(form)
        row = QHBoxLayout()
        open_logs = QPushButton("Open log folder")
        open_logs.clicked.connect(lambda: _open_folder(self.context.paths.log_dir))
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_log_view)
        row.addWidget(open_logs)
        row.addWidget(refresh)
        row.addStretch(1)
        card.add_layout(row)
        card = section.card("Recent log entries")
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setProperty("role", "mono")
        self.log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.log_view.setMinimumHeight(260)
        card.add_widget(self.log_view)
        return section

    def _refresh_log_view(self) -> None:
        self.log_view.setPlainText("\n".join(list(ring_buffer.records)[-400:]))
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _advanced(self) -> _Section:
        section = _Section("Advanced")
        card = section.card("Command preview")
        box = QCheckBox("Show arguments Genmap adds on its own (output file, progress interval)")
        card.add_widget(box)
        self._bind_check(section, box, "advanced", "show_managed_arguments")
        card = section.card("Concurrency")
        multi = QCheckBox("Allow more than one scan at a time")
        card.add_widget(multi)
        self._bind_check(section, multi, "advanced", "allow_multiple_scans")
        form = form_layout()
        limit = QSpinBox()
        limit.setRange(1, 4)
        form.addRow("Maximum concurrent scans", limit)
        self._bind_spin(section, limit, "scanning", "max_concurrent_scans")
        card.add_layout(form)
        card.add_widget(hint("Parallel scans compete for bandwidth and can distort each other's timing. One at a time is the safe default."))
        return section

    # Environment -------------------------------------------------------------

    def _save_and_probe(self) -> None:
        if self._dirty:
            if not self.save():
                return
        self.context.refresh_environment()

    def _show_environment(self, env: NmapEnvironment) -> None:
        self.nmap_status.setText(
            f"Using {env.executable}" if env.usable else "Nmap is not usable. See the diagnostics below."
        )
        version = env.version
        self.nmap_summary.set_value("Version", str(version) if version else "Not found", status=None if version else "error")
        self.nmap_summary.set_value("Location", str(env.executable) if env.executable else "")
        self.nmap_summary.set_value("Found via", (env.executable_source or "").replace("_", " "))
        self.nmap_summary.set_value("Data directory", str(env.data_directory) if env.data_directory else "Not found")
        self.nmap_summary.set_value("Platform", version.platform or "" if version else "")
        self.nmap_summary.set_value("Compiled with", " ".join(version.compiled_with) if version else "")
        driver = env.capture_driver
        self.nmap_summary.set_value("Packet capture", f"{driver.name}: {driver.detail}" if driver else "")
        from genmap.nmap.privileges import privilege_label

        self.nmap_summary.set_value("Privileges", privilege_label(env.privileges))
        self.diagnostics.set_diagnostics(env.diagnostics)

        palette = self.context.theme.palette
        from PyQt6.QtGui import QColor

        capabilities = list(env.capabilities)
        self.capabilities.setRowCount(len(capabilities))
        for row, capability in enumerate(capabilities):
            state = {True: "Yes", False: "No", None: "Unknown"}[capability.available]
            color = {True: palette.success, False: palette.danger, None: palette.warning}[capability.available]
            items = [QTableWidgetItem(capability.label), QTableWidgetItem(state), QTableWidgetItem(capability.detail)]
            items[1].setForeground(QColor(color))
            items[2].setToolTip(capability.detail)
            for column, item in enumerate(items):
                self.capabilities.setItem(row, column, item)
        self.capabilities.resizeColumnToContents(0)
        self.capabilities.resizeColumnToContents(1)
        self.capabilities.resizeRowsToContents()

        interfaces = env.interfaces.interfaces if env.interfaces else []
        self.interfaces.setRowCount(len(interfaces))
        for row, iface in enumerate(interfaces):
            for column, value in enumerate((iface.device, iface.short_name, iface.address or "", iface.interface_type, "up" if iface.is_up else "down", iface.mac or "")):
                self.interfaces.setItem(row, column, QTableWidgetItem(value))
        self.interfaces.resizeColumnsToContents()
        routes = env.interfaces.routes if env.interfaces else []
        self.routes.setRowCount(len(routes))
        for row, route in enumerate(routes):
            for column, value in enumerate((route.destination, route.device, "" if route.metric is None else str(route.metric), route.gateway or "")):
                self.routes.setItem(row, column, QTableWidgetItem(value))
        self.routes.resizeColumnsToContents()
