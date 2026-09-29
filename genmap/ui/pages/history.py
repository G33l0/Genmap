"""Scan history backed by the scan index database."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import QSortFilterProxyModel, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QDesktopServices, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from genmap.core.scan_config import ScanConfiguration
from genmap.engine.run_store import RunStatus
from genmap.errors import GenmapError
from genmap.storage.models import Scan
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.scan_monitor import format_duration
from genmap.ui.widgets.common import PageHeader, label
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.inputs import EnumCombo, TextField

ROLE_RUN_ID = Qt.ItemDataRole.UserRole + 1
ROLE_SORT = Qt.ItemDataRole.UserRole + 2

_STATUS_COLOR = {
    RunStatus.COMPLETED.value: "success",
    RunStatus.COMPLETED_WITH_WARNINGS.value: "warning",
    RunStatus.FAILED.value: "danger",
    RunStatus.CRASHED.value: "danger",
    RunStatus.CANCELLED.value: "text_muted",
    RunStatus.TIMED_OUT.value: "warning",
    RunStatus.RUNNING.value: "info",
    RunStatus.INTERRUPTED.value: "warning",
}


def status_label(value: str) -> str:
    try:
        return RunStatus(value).label
    except ValueError:
        return value


def local_time(value: Optional[datetime]) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S") if value else ""


class HistoryPage(BasePage):
    page_key = "history"
    page_title = "Scan History"

    open_requested = pyqtSignal(str)
    duplicate_requested = pyqtSignal(object)  # ScanConfiguration
    rerun_requested = pyqtSignal(object)  # ScanConfiguration
    monitor_requested = pyqtSignal(str)
    report_requested = pyqtSignal(str)

    HEADERS = ["Started", "Targets", "Profile", "Status", "Duration", "Hosts up", "Open ports", "Tags", "Nmap", "Command"]

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._scans: dict[str, Scan] = {}
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "Scan History",
            "Every scan keeps its configuration, command, console output, and raw Nmap XML. Search covers targets, hosts found, commands, profiles, and tags.",
        ))

        filters = QHBoxLayout()
        self.search = TextField("Search targets, hostnames, addresses, commands, tags...")
        self.status_filter = EnumCombo([("Any status", "")] + [(s.label, s.value) for s in RunStatus if s != RunStatus.PENDING])
        self.tag_filter = EnumCombo([("Any tag", "")])
        filters.addWidget(self.search, 1)
        filters.addWidget(self.status_filter)
        filters.addWidget(self.tag_filter)
        outer.addLayout(filters)

        toolbar = QHBoxLayout()
        self.open_button = QPushButton("Open results")
        self.open_button.setProperty("accent", True)
        self.report_button = QPushButton("Report...")
        self.report_button.setToolTip("Create an HTML, JSON, CSV, or XML report for this scan")
        self.rerun_button = QPushButton("Rerun")
        self.rerun_button.setToolTip("Run the same configuration again after confirmation")
        self.duplicate_button = QPushButton("Edit copy")
        self.duplicate_button.setToolTip("Load this configuration into New Scan without starting it")
        self.tags_button = QPushButton("Tags...")
        self.folder_button = QPushButton("Show files")
        self.delete_button = QPushButton("Delete")
        self.delete_button.setProperty("danger", True)
        for button in (self.open_button, self.report_button, self.rerun_button, self.duplicate_button, self.tags_button, self.folder_button, self.delete_button):
            toolbar.addWidget(button)
        toolbar.addStretch(1)
        outer.addLayout(toolbar)

        self.model = QStandardItemModel(0, len(self.HEADERS))
        self.model.setHorizontalHeaderLabels(self.HEADERS)
        self.proxy = QSortFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(ROLE_SORT)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.doubleClicked.connect(lambda _index: self._open())
        self.table.setAccessibleName("Scan history")
        outer.addWidget(self.table, 1)
        self.status = label("", role="small")
        outer.addWidget(self.status)

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(250)
        self._search_timer.timeout.connect(self.reload)
        self.search.textChanged.connect(self._search_timer.start)
        self.status_filter.currentIndexChanged.connect(self.reload)
        self.tag_filter.currentIndexChanged.connect(self.reload)
        self.open_button.clicked.connect(self._open)
        self.report_button.clicked.connect(self._report)
        self.rerun_button.clicked.connect(self._rerun)
        self.duplicate_button.clicked.connect(self._duplicate)
        self.tags_button.clicked.connect(self._edit_tags)
        self.folder_button.clicked.connect(self._show_folder)
        self.delete_button.clicked.connect(self._delete)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._update_buttons())
        context.index_changed.connect(self._reload_if_visible)
        self._update_buttons()

    def on_shown(self) -> None:
        self.reload()

    def _reload_if_visible(self) -> None:
        if self.isVisible():
            self.reload()

    def _refresh_tag_filter(self) -> None:
        current = self.tag_filter.current_value()
        self.tag_filter.blockSignals(True)
        self.tag_filter.clear()
        self.tag_filter.addItem("Any tag", "")
        for tag in self.context.scan_index.all_tags():
            self.tag_filter.addItem(tag, tag)
        self.tag_filter.set_current_value(current if current is not None else "")
        self.tag_filter.blockSignals(False)

    def reload(self) -> None:
        self._search_timer.stop()
        self._refresh_tag_filter()
        selected = set(self._selected_ids())
        try:
            scans = self.context.scan_index.list_scans(
                search=self.search.text(),
                status=str(self.status_filter.current_value() or "") or None,
                tag=str(self.tag_filter.current_value() or "") or None,
            )
        except Exception as exc:
            self.status.setText(f"History could not be loaded: {exc}")
            return
        self._scans = {s.run_id: s for s in scans}
        self.model.removeRows(0, self.model.rowCount())
        palette = self.context.theme.palette
        for scan in scans:
            duration = (scan.finished_at - scan.started_at).total_seconds() if scan.started_at and scan.finished_at else None
            status_text = status_label(scan.status) + (" (files missing)" if scan.folder_missing else "")
            tags = ", ".join(t.name for t in scan.tags)
            values = [
                (local_time(scan.created_at), scan.created_at.timestamp()),
                (scan.target_summary, scan.target_summary.lower()),
                (scan.profile_name or "", (scan.profile_name or "").lower()),
                (status_text, scan.status),
                (format_duration(duration) if duration is not None else "", duration or 0),
                (str(scan.hosts_up) if scan.results_indexed or scan.hosts_total else "", scan.hosts_up),
                (str(scan.open_ports) if scan.results_indexed or scan.hosts_total else "", scan.open_ports),
                (tags, tags.lower()),
                (scan.nmap_version or "", scan.nmap_version or ""),
                (scan.command_display or "", ""),
            ]
            row = []
            for text, sort in values:
                item = QStandardItem(text)
                item.setEditable(False)
                item.setData(scan.run_id, ROLE_RUN_ID)
                item.setData(sort, ROLE_SORT)
                row.append(item)
            color_name = "warning" if scan.folder_missing else _STATUS_COLOR.get(scan.status)
            if color_name:
                row[3].setForeground(QColor(getattr(palette, color_name)))
            tooltip = "\n".join(p for p in (scan.error_message, scan.error_remedy) if p)
            if scan.folder_missing:
                tooltip = "The scan folder was removed from disk; only the indexed summary remains.\n" + tooltip
            row[3].setToolTip(tooltip.strip())
            row[9].setToolTip(scan.command_display or "")
            self.model.appendRow(row)
        self.table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self.table.resizeColumnsToContents()
        for column, width in ((1, 260), (9, 400)):
            if self.table.columnWidth(column) > width:
                self.table.setColumnWidth(column, width)
        if selected:
            for row in range(self.proxy.rowCount()):
                if self.proxy.index(row, 0).data(ROLE_RUN_ID) in selected:
                    self.table.selectRow(row)
        elif self.proxy.rowCount():
            self.table.selectRow(0)
        filtered = bool(self.search.text().strip() or self.status_filter.current_value() or self.tag_filter.current_value())
        total = self.context.scan_index.stats().scans
        size_mb = (self.context.run_store.total_size_bytes() + self.context.database.size_bytes()) / 1_000_000
        shown = f"{len(scans)} of {total} scans" if filtered else f"{total} scan{'s' if total != 1 else ''}"
        self.status.setText(f"{shown}, {size_mb:.1f} MB on disk in {self.context.paths.data_dir}")
        self._update_buttons()

    def _selected_ids(self) -> list[str]:
        ids: list[str] = []
        selection = self.table.selectionModel()
        if selection is None:
            return ids
        for index in selection.selectedRows():
            run_id = index.data(ROLE_RUN_ID)
            if run_id and run_id not in ids:
                ids.append(run_id)
        return ids

    def _current(self) -> Optional[Scan]:
        ids = self._selected_ids()
        return self._scans.get(ids[0]) if ids else None

    def _running(self, run_id: str) -> bool:
        job = self.context.engine.job(run_id)
        return job is not None and job.is_running

    def _update_buttons(self) -> None:
        ids = self._selected_ids()
        single = len(ids) == 1
        scan = self._current()
        running = scan is not None and self._running(scan.run_id)
        has_files = scan is not None and not scan.folder_missing
        self.open_button.setEnabled(single and (running or has_files))
        self.open_button.setText("Show live scan" if running else "Open results")
        self.report_button.setEnabled(single and has_files and not running)
        self.rerun_button.setEnabled(single and not running)
        self.duplicate_button.setEnabled(single)
        self.tags_button.setEnabled(single)
        self.folder_button.setEnabled(single and has_files)
        self.delete_button.setEnabled(bool(ids) and not any(self._running(i) for i in ids))

    def _open(self) -> None:
        scan = self._current()
        if scan is None:
            return
        if self._running(scan.run_id):
            self.monitor_requested.emit(scan.run_id)
        elif not scan.folder_missing:
            self.open_requested.emit(scan.run_id)

    def _config_of(self, scan: Scan) -> Optional[ScanConfiguration]:
        try:
            return ScanConfiguration.model_validate(scan.configuration)
        except Exception as exc:
            show_exception(self, exc, "Configuration could not be loaded")
            return None

    def _rerun(self) -> None:
        scan = self._current()
        config = self._config_of(scan) if scan else None
        if config is not None:
            self.rerun_requested.emit(config)

    def _duplicate(self) -> None:
        scan = self._current()
        config = self._config_of(scan) if scan else None
        if config is not None:
            self.duplicate_requested.emit(config)

    def _report(self) -> None:
        scan = self._current()
        if scan is not None:
            self.report_requested.emit(scan.run_id)

    def _edit_tags(self) -> None:
        scan = self._current()
        if scan is None:
            return
        current = ", ".join(t.name for t in scan.tags)
        known = ", ".join(self.context.scan_index.all_tags())
        text, ok = QInputDialog.getText(
            self,
            "Tags",
            "Comma separated tags for this scan" + (f"\nExisting tags: {known}" if known else ""),
            text=current,
        )
        if not ok:
            return
        try:
            self.context.scan_index.set_tags(scan.run_id, text.split(","))
        except GenmapError as exc:
            show_exception(self, exc, "Tags not saved")
            return
        self.reload()

    def _show_folder(self) -> None:
        scan = self._current()
        if scan is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.context.run_store.run_directory(scan.run_id))))

    def _delete(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        noun = "this scan" if len(ids) == 1 else f"these {len(ids)} scans"
        answer = QMessageBox.warning(
            self,
            "Delete scans",
            f"Permanently delete {noun}? The stored XML, console output, configuration, and indexed results will be removed. Reports you exported elsewhere are kept. This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        failures: list[str] = []
        for run_id in ids:
            try:
                self.context.delete_scan(run_id)
            except GenmapError as exc:
                failures.append(f"{run_id}: {exc.details or exc.message}")
        self.reload()
        if failures:
            show_exception(self, GenmapError("Some scans could not be deleted.", details="\n".join(failures)), "Delete failed")

    def _context_menu(self, position) -> None:
        if not self._selected_ids():
            return
        menu = QMenu(self)
        for button in (self.open_button, self.report_button, self.rerun_button, self.duplicate_button, self.tags_button, self.folder_button, self.delete_button):
            action = menu.addAction(button.text(), button.click)
            action.setEnabled(button.isEnabled())
        menu.exec(self.table.viewport().mapToGlobal(position))
